# 容器镜像准入策略评估服务

基于 Spring Boot 的本地可运行服务：综合镜像标识、软件成分（SBOM）、漏洞扫描、
签名/证明材料与策略状态，产出**可解释**的镜像准入结论。

## 构建与运行

```bash
mvn compile          # 编译
mvn test             # 运行全部测试（不依赖外部服务或真实凭据）
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8080"  # 本地启动
```

### REST 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/admission/evaluate` | 评估镜像准入；拒绝时返回 HTTP 422 与可区分的 `denyReason` |
| GET  | `/api/v1/admission/policies` | 查看当前策略快照（含版本号） |
| PUT  | `/api/v1/admission/policies` | 原子替换全部策略，版本号递增 |
| GET  | `/api/v1/admission/audit`    | 查看审计记录 |

评估请求示例：

```json
{
  "requestId": "req-1",
  "imageRef": "reg.example.com/team/app:1.0@sha256:<64hex>",
  "resolvedDigest": "sha256:<64hex>",
  "evidenceList": [
    {"id": "scan-1", "type": "VULN_SCAN", "imageDigest": "sha256:<64hex>",
     "formatVersion": 2, "issuedAt": "2026-09-25T00:00:00Z",
     "expiresAt": "2027-09-25T00:00:00Z",
     "attributes": {"scanner": "trivy", "criticalCount": "0"}},
    {"id": "sig-1", "type": "SIGNATURE", "imageDigest": "sha256:<64hex>",
     "formatVersion": 2, "issuedAt": "2026-09-25T00:00:00Z",
     "expiresAt": "2027-09-25T00:00:00Z",
     "attributes": {"signature": "...", "publicKeyId": "key-1"}}
  ]
}
```

结论示例（每条结论都可还原判定依据）：

```json
{"verdict": "ALLOW", "denyReason": null, "imageRef": "reg.example.com/team/app:1.0@sha256:...",
 "policyVersion": 1, "matchedRuleIds": ["default-require-scan-and-signature"],
 "evidenceIds": ["scan-1", "sig-1"], "explanation": "命中规则 ...，必需证据齐备"}
```

## 策略优先级与冲突语义

- 策略由若干**规则**组成，每条规则含 `scopePattern`、`priority`、`effect`（ALLOW/DENY）
  与 `requiredEvidence`。
- 作用域模式针对镜像的 `registry/repository` 全名匹配：`**` 匹配任意（含跨段）字符，
  `*` 匹配单段内字符，其余按字面匹配。
- 同一镜像命中多条规则时，排序**确定**：优先级降序，其次 `ruleId` 字典序升序。
- 冲突处理：排序后**第一条规则的效果生效**（高优先级胜出；同优先级时 ruleId 小者胜出），
  结果可重现。命中的全部规则 ID 都会记录在结论与审计中。
- **策略缺失不静默放行**：没有任何规则命中时拒绝（`NO_APPLICABLE_POLICY`）。

## 证据兼容与失效规则

证据校验顺序固定（保证同一证据的拒绝原因确定）：

1. **完整性**：缺 `id`/`type`/`imageDigest` 或类型必填属性（SBOM 需 `format`；
   VULN_SCAN 需 `scanner`+`criticalCount`；SIGNATURE 需 `signature`+`publicKeyId`；
   ATTESTATION 需 `predicateType`）→ `EVIDENCE_INCOMPLETE`。
2. **摘要绑定**：证据 `imageDigest` 必须等于目标镜像摘要，否则 → `EVIDENCE_UNBOUND`。
3. **过期**：`expiresAt` 不晚于当前时间 → `EVIDENCE_EXPIRED`。
4. **格式版本**：`formatVersion` 必须 ∈ {1, 2}（`Evidence.SUPPORTED_FORMAT_VERSIONS`），
   过旧或过新 → `EVIDENCE_STALE_FORMAT`。

镜像级规则：

- **标签漂移**：`imageRef` 中的摘要与准入时刻仓库解析摘要 `resolvedDigest` 不一致
  → `TAG_DRIFT`。
- **摘要冲突**：请求内证据绑定到多个不同摘要 → `DIGEST_MISMATCH`。
- 镜像标识无法解析 → `INVALID_IMAGE_REF`；缺少可绑定证据的摘要 → `INVALID_REQUEST`。
- 必需证据类型无任何有效证据时：若存在该类型但无效的证据，报告其具体无效原因
  （过期/旧格式/不完整/未绑定），否则报告 `MISSING_EVIDENCE`。
- **失效**：证据过期后，依赖它的旧缓存结论立即失效（见下节）；新增证据会改变证据指纹，
  同样使旧结论失效。

## 并发与缓存保证

- **一致快照**：`PolicyStore` 用 `AtomicReference` 持有不可变 `PolicySnapshot`，
  更新整体替换、版本号单调递增；每次评估只基于一个快照，并发更新不会出现半新半旧。
- **缓存失效**：评估缓存键 = 镜像标识 + 解析摘要 + **策略版本** + **证据指纹**
  （证据 id/类型/摘要/格式版本/过期时间）。策略变更或证据新增/变更后旧键不再命中；
  缓存条目另带 `validUntil`（证据最早过期时间），证据过期后旧结论不得继续生效。
- **幂等与副作用**：同一缓存键的并发评估通过 `ConcurrentHashMap.compute` 只计算一次；
  审计以 `requestId` 为幂等键（`putIfAbsent`），同一镜像的并发或重复请求
  **只产生一条审计记录**。
- **可重现性**：输入与策略均未变化时，重复评估结论一致（确定性排序 + 固定校验顺序）。
- **审计可还原**：每条审计记录包含镜像标识、策略版本、命中规则、证据 ID 与判定解释；
  日志同步打印上述字段。

## 错误分类（拒绝原因）

| denyReason | 含义 |
|---|---|
| `INVALID_IMAGE_REF` | 镜像标识无法解析（非法 digest/tag/repo） |
| `INVALID_REQUEST` | 请求缺 requestId 或缺少可绑定证据的摘要 |
| `NO_APPLICABLE_POLICY` | 无任何策略规则命中（默认拒绝） |
| `POLICY_EXPLICIT_DENY` | 命中显式 DENY 规则 |
| `TAG_DRIFT` | 标签当前解析摘要与请求摘要不一致 |
| `DIGEST_MISMATCH` | 证据绑定的摘要互相冲突 |
| `EVIDENCE_UNBOUND` | 证据未绑定到目标镜像摘要 |
| `EVIDENCE_EXPIRED` | 证据已过期 |
| `EVIDENCE_STALE_FORMAT` | 证据格式版本不受支持（过旧/过新） |
| `EVIDENCE_INCOMPLETE` | 证据清单不完整（缺必填字段/属性） |
| `MISSING_EVIDENCE` | 缺少必需的证据类型 |

## 本地验证方法

```bash
mvn test
```

测试覆盖（全部使用内存实现与固定时钟，不依赖外部服务或真实凭据）：

- `ImageRefTest`：镜像标识解析（含 registry 端口、非法输入）。
- `EvidenceValidatorTest`：过期、未绑定、旧格式、不完整清单。
- `PolicyEngineTest`：作用域 glob 匹配、优先级与同优先级确定性排序。
- `AdmissionServiceTest`（18 例）：正常准入、标签漂移、摘要冲突、过期/缺失/旧格式/
  不完整证据、策略冲突（DENY 优先）、无命中策略、重复评估确定性、策略更新使缓存失效、
  证据过期使缓存失效、新增证据改变结论、并发重复请求只产生一条审计、
  并发策略更新与评估的快照一致性、审计记录可还原策略版本/证据/命中规则。
- `ApplicationTests`：Spring 上下文加载。
