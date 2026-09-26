# 容器镜像准入策略评估服务

一个可本地运行的 Spring Boot 服务。给定**镜像标识、软件成分（SBOM）、漏洞扫描、签名/证明材料**
与当前**策略快照**，产生**可解释**的准入结论（ALLOW / DENY），并提供策略版本化、
证据绑定校验、并发一致性、结论缓存与审计能力。整个服务自包含、无外部服务依赖、不需要真实凭据。

- Java 21 + Spring Boot 3.4，内存存储（`ConcurrentHashMap` + copy-on-write 快照）
- 入口：`com.github.lisama569.containerimageadmissionservicejava.Application`

---

## 1. 模型

| 概念 | 说明 |
| --- | --- |
| `ImageRef` | `registry / repository / tag / digest`，digest 是权威内容标识 |
| `ImageManifest` | 清单摘要 + 条目（name/digest/size），必须完整 |
| `Evidence` | 四类：`SBOM`、`VULN_SCAN`、`SIGNATURE`、`ATTESTATION`；含绑定摘要、创建/过期时间、`formatVersion`、签名者、证明类型、包清单、漏洞计数 |
| `PolicyDefinition` | `name / version / enabled / priority / scope / rules[]`，按 name 版本化 |
| `PolicyRule` | `id / priority / effect(ALLOW|DENY) / constraints` |
| `PolicySnapshot` | `snapshotVersion + createdAt + policies`，**不可变**，一次评估全程只使用一个快照 |
| `AdmissionResult` | 结论、拒绝原因码、命中规则及逐条发现、证据 id、缓存键、快照版本、时间 |

---

## 2. 策略优先级与冲突语义

作用域三段（registry/repository/tag）均为大小写不敏感的 glob（`*`、`?`），
null/空白等价于 `*`；三段同时命中才算策略命中。

1. 只考虑 `enabled=true` 的策略。**没有任何已启用策略 → `POLICY_NOT_FOUND`**；
   有策略但全部不命中作用域 → **`NO_RULE_MATCHED`**。二者均 fail-closed。
2. 汇总所有命中策略的规则，按规则的 `rule.priority`（**数值越小优先级越高**）取最高优先级组，
   其余低优先级规则本次不参与判定。
3. 同组（同规则优先级）内规则次序确定：先按 `policy.priority`，再按 `policy.name`、`rule.id`。
4. 规则语义随 `effect` 不同：
   - **ALLOW**：约束是“必须全部满足的要求”。任一不满足即规则不成立，附带具体证据原因码。
   - **DENY**：约束是“正向触发条件”。条件成立（如存在达到阈值的漏洞、存在禁用成分、
     出现有效 SBOM/扫描等）规则才成立；证据缺失**不**触发否决，只意味着该否决不成立。
5. 判定：
   - 同优先级组内 **ALLOW 与 DENY 同时成立 → `POLICY_CONFLICT`，fail-closed 拒绝**
     （跨策略的同优先级冲突同样如此检测）。注意：仅当“一条规则要求放行、另一条规则要求拒绝”
     且二者结论无法同时满足时才算冲突；**多条 DENY 同时触发不是冲突**（结论一致，按 `RULE_VIOLATION` 拒绝）；
   - 有 DENY 触发、无 ALLOW 成立 → 按该 DENY 的具体触发原因拒绝（通常是 `RULE_VIOLATION`，
     漏洞阈值触发为 `VULN_THRESHOLD_EXCEEDED` 等）；
   - 组内全部为 ALLOW 且全部满足 → `ALLOW`；
   - 组内全部为 DENY 且没有一条触发 → 不构成否决，`ALLOW`；
   - 组内有 ALLOW 但未全部满足、又无 DENY 触发 → 按首个具体原因拒绝。
6. 策略写入：同名只接受**严格递增**的 `version`，回退/重复旧版本返回 `POLICY_INVALID`。
   每次成功写入/删除都使全局 `snapshotVersion +1`。

---

## 3. 证据兼容与失效规则

### 摘要归一化（`DigestNormalizer`）
- `trim` + 小写；标准形态 `algorithm:hex`；
- 裸 64 位十六进制串兼容补全为 `sha256:<hex>`（兼容旧式客户端）；
- 算法非法、长度不符、空白 → `INPUT_INVALID`。

### 绑定与一致性（全局硬校验，发生在策略判定之前）
- **tag-only 引用（无 digest）→ `TAG_DRIFT`**：标签可变，无法固定内容；
- 缺少清单 → `MANIFEST_INCOMPLETE`；清单摘要与请求摘要不一致 →
  **`EVIDENCE_DIGEST_MISMATCH`**；条目缺 name/digest/size → `MANIFEST_INCOMPLETE`；
- 每条证据的 `boundDigest` 都必须归一化后等于请求摘要，否则 **`EVIDENCE_DIGEST_MISMATCH`**。

### 证据有效性（按规则需要逐类校验，原因彼此可区分）
| 情形 | 原因码 |
| --- | --- |
| 缺 SBOM / 通用证据 | `EVIDENCE_MISSING` |
| 缺漏洞扫描 / 扫描无计数（ALLOW 规则下） | `VULN_SCAN_MISSING` |
| 缺签名 | `SIGNATURE_MISSING` |
| 缺证明材料 | `ATTESTATION_MISSING` |
| 证明未覆盖必需类型 | `ATTESTATION_TYPE_MISSING` |
| 漏洞最高严重级超过 ALLOW 上限 | `VULN_THRESHOLD_EXCEEDED` |
| 签名过期 | `SIGNATURE_EXPIRED` |
| 其他证据过期 / 超过 `maxEvidenceAge` | `EVIDENCE_EXPIRED` |
| 证据 `formatVersion < 1`（旧格式） | `EVIDENCE_STALE` |
| 签名者不在 `trustedSigners` | `SIGNATURE_UNTRUSTED_SIGNER` |
| 含 `forbiddenPackages` / DENY 条件触发 | `RULE_VIOLATION` |
| 证据不完整（如 SBOM 无包清单） | `EVIDENCE_INSUFFICIENT` |

### 确定性与失效
- **证据指纹**（SHA-256）覆盖 id/类型/绑定摘要/时间戳/过期/格式版本/签名者/证明类型/包/计数，
  与列表顺序无关；
- 缓存键 = `snapshotVersion | 归一化摘要 | 证据指纹`。输入与策略均不变 →
  结论字节级一致并命中缓存；**新增/删除证据、证据过期或轮换、任一字段变化都会改变指纹，
  旧键对应的旧结论不再被使用**；策略变更时存储层还会整体清空缓存。

---

## 4. 并发与缓存保证

- `PolicyStore`：copy-on-write 维护唯一当前快照，写入 `synchronized` 串行化、
  版本号单调递增；读端拿到的是不可变快照，**评估期间发生的策略更新不会影响本次评估**。
- 任何成功的策略写入/删除立即 `AdmissionCache.invalidateAll()`，
  **旧快照结论绝不继续生效**。
- `AdmissionService`：
  - 同一 `requestId` 的**并发请求**经 per-key 锁合并为一次真实评估；
  - 同一 `requestId` 的**重复请求**直接返回首次结论（`computeIfAbsent` 幂等），
    **审计记录只写一条，无重复副作用**；
  - 不同 requestId、相同（快照+摘要+证据指纹）共享同一份不可变缓存结论，但各记一条审计。

---

## 5. 审计

`/api/audit` 可按 requestId 查询或列出全部。每条 `AuditRecord` 保存：
recordId、requestId、镜像引用与摘要、**策略快照版本**、完整 `AdmissionResult`
（**命中规则及每条规则的 effect/是否成立/findings、证据 id 列表、缓存键**）、记录时间，
足以还原“基于哪个策略版本、哪些证据、哪条规则”做出判定。

日志（SLF4J）在评估、拒绝、审计、缓存命中、重复请求、策略错误时打印：
**镜像标识、策略快照版本、命中策略/规则、证据标识、决策与原因**。

---

## 6. 错误分类（HTTP）

业务结论类拒绝（镜像相关）HTTP 200，响应体 `decision=DENY` + `reason`；
请求/策略类错误返回 4xx：

| 错误码 | HTTP | 含义 |
| --- | --- | --- |
| `INPUT_INVALID` | 400 | 请求体/枚举/摘要等字段非法 |
| `POLICY_INVALID` | 400 | 策略字段非法或版本未递增 |
| `POLICY_NOT_FOUND` | 404 | 管理接口查无此策略（评估接口中作为 DENY 原因出现在 200 响应） |
| 其他业务码 | 422 | 管理类语义错误兜底 |
| `INTERNAL_ERROR` | 500 | 未预期异常 |

---

## 7. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| PUT | `/api/policies/{name}` | 创建/更新策略（版本须递增） |
| GET | `/api/policies`、`/api/policies/{name}` | 查询 |
| DELETE | `/api/policies/{name}` | 删除（快照版本 +1，缓存失效） |
| POST | `/api/admission/evaluate` | 准入评估 |
| GET | `/api/audit`、`/api/audit/{requestId}` | 审计查询 |

### 策略示例

```json
PUT /api/policies/production-baseline
{
  "version": 1,
  "enabled": true,
  "priority": 100,
  "scope": { "registryPattern": "registry.example.com", "repositoryPattern": "prod/*", "tagPattern": "*" },
  "rules": [
    {
      "id": "strict-allow",
      "priority": 100,
      "effect": "ALLOW",
      "constraints": {
        "requireSbom": true,
        "requireVulnScan": true,
        "maxSeverity": "HIGH",
        "requireSignature": true,
        "trustedSigners": ["ci-bot@example.com"],
        "requiredAttestations": ["slsa/provenance"],
        "maxEvidenceAgeSeconds": 2592000
      }
    },
    {
      "id": "deny-critical",
      "priority": 10,
      "effect": "DENY",
      "constraints": { "requireVulnScan": true, "maxSeverity": "CRITICAL" }
    }
  ]
}
```

### 评估示例

```json
POST /api/admission/evaluate
{
  "requestId": "req-001",
  "image": "registry.example.com/prod/app:v1",
  "digest": "sha256:<64hex>",
  "manifest": {
    "digest": "sha256:<64hex>",
    "entries": [ { "name": "layer.tar", "digest": "sha256:<64hex>", "size": 123 } ]
  },
  "evidences": [
    { "id": "sbom-1", "type": "SBOM", "boundDigest": "sha256:<64hex>",
      "createdAt": "2026-09-25T00:00:00Z", "expiresAt": "2026-10-26T00:00:00Z",
      "formatVersion": 1, "packages": ["libfoo-1.0"] },
    { "id": "scan-1", "type": "VULN_SCAN", "boundDigest": "sha256:<64hex>",
      "createdAt": "2026-09-25T00:00:00Z", "expiresAt": "2026-10-26T00:00:00Z",
      "formatVersion": 1, "vulnerabilityCounts": { "LOW": 2 } },
    { "id": "sig-1", "type": "SIGNATURE", "boundDigest": "sha256:<64hex>",
      "createdAt": "2026-09-25T00:00:00Z", "expiresAt": "2026-10-26T00:00:00Z",
      "formatVersion": 1, "signer": "ci-bot@example.com" },
    { "id": "att-1", "type": "ATTESTATION", "boundDigest": "sha256:<64hex>",
      "createdAt": "2026-09-25T00:00:00Z", "expiresAt": "2026-10-26T00:00:00Z",
      "formatVersion": 1, "attestationTypes": ["slsa/provenance"] }
  ]
}
```

响应含 `decision`、`reason`、`message`、`policySnapshotVersion`、逐条 `ruleHits[].findings`、
`evidenceIds`、`cacheKey`、`fromCache` 与评估时间。

---

## 8. 本地验证

```bash
# 运行全部测试（无外部服务/真实凭据；共 50 个用例）
mvn test

# 启动（默认 8080；admission.seed-defaults=true 时预置两条演示策略）
mvn spring-boot:run
# 关闭演示种子：-Dspring-boot.run.arguments=--admission.seed-defaults=false

# 冒烟
curl -s localhost:8080/api/policies | jq .
curl -s localhost:8080/api/audit | jq .
```

测试覆盖：
- 正常准入；
- 标签漂移、清单/证据摘要冲突、清单不完整；
- 证据缺失（四类可区分）、签名过期/不受信、证据过期、旧格式证据、证明类型缺失；
- 漏洞阈值、禁止成分、裸 hex 摘要兼容；
- 策略不存在/作用域不命中、高优先级 DENY 否决、同优先级（含跨策略）ALLOW/DENY 冲突；
- 策略版本不可回退、并发更新串行化与快照不可变；
- 重复请求幂等、同 requestId 并发只产生一条审计、证据变化与策略变更使旧结论失效；
- Web 层状态码与错误分类。
