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
| PUT  | `/api/v1/admission/policies` | 兼容接口：内部走“校验暂存 + 原子发布”，版本号递增 |
| POST | `/api/v1/admission/policies/preview` | **预演**：用候选策略对一批目标做假设性评估，返回结论变化 |
| POST | `/api/v1/admission/policies/stage` | 暂存候选策略（当场校验，不生效），返回草稿版本号 |
| POST | `/api/v1/admission/policies/publish` | 将已暂存候选策略**原子**发布到线上 |
| POST | `/api/v1/admission/policies/rollback` | **整体回滚**到上一次发布前快照 |
| POST | `/api/v1/admission/exceptions` | 创建带到期时间的临时例外 |
| GET  | `/api/v1/admission/exceptions` | 查看全部例外（含已撤销/已过期） |
| DELETE | `/api/v1/admission/exceptions/{id}` | 撤销例外（立即生效） |
| GET  | `/api/v1/admission/audit`    | 查看审计记录 |

> HTTP 语义：评估拒绝 = **422**（带 `denyReason`）；候选策略/例外本身填错 = **400**
> （`INVALID_CANDIDATE_POLICY` / `INVALID_REQUEST`，body 中 `issues` 列出全部问题）；
> 发布/回滚状态错误（无草稿、无可回滚目标）= **409**。

### 预演（先看结果，不碰线上）

`POST /policies/preview` 请求体：候选策略 + 一组与评估接口同构的目标
（镜像、解析摘要、证据）。服务端先用当前线上快照、再用候选快照各静默评估一次，
逐项给出 `currentVerdict/currentReason`、`candidateVerdict/candidateReason` 与 `changed`。

```json
{
  "candidatePolicies": [
    {"name": "candidate", "version": 2, "rules": [
      {"ruleId": "candidate-deny-team", "scopePattern": "reg.example.com/team/**",
       "priority": 100, "effect": "DENY", "requiredEvidence": []}]}
  ],
  "targets": [
    {"requestId": "t1", "imageRef": "reg.example.com/team/app:1.0@sha256:<64hex>",
     "resolvedDigest": "sha256:<64hex>", "evidenceList": [ ... ]}
  ]
}
```

预演规则：

- **只看结果**：预演通过内部的“静默评估”完成，**不读/写线上评估缓存、不写审计日志**，
  因此不会影响线上判定，也不会留下正式判定记录；
- 候选快照版本号固定为 `0`（`PreviewReport.candidateVersion`），明确标识“尚未生效”，
  不与任何真实线上版本混淆；
- 候选策略在预演前先经完整校验，非法时返回 400 并一次性列出全部问题，
  **绝不静默放过**；`changed` 在 verdict 变化、或同为 DENY 但拒绝原因变化时为 true。

### 受控发布与回滚

流程为 **stage（暂存校验）→ publish（原子发布）→ 必要时 rollback（整体回滚）**：

- **暂存即校验**：`/policies/stage` 对候选策略做完整校验（策略/规则非空、ruleId 非空且全局唯一、
  scopePattern/effect 非空、requiredEvidence 元素非空）。任何一条不通过都会被整体拒绝（400），
  非法策略无法进入发布；暂存期间线上判定完全不变。
- **原子切换**：`/policies/publish` 通过 `PolicyStore` 对不可变快照做**整体引用替换**。
  发布进行中并发过来的评估，要么整体拿到发布前快照、要么整体拿到发布后快照，
  **不会出现半新半旧的中间态**。
- **整体回滚**：`/policies/rollback` 恢复上一次发布前快照，**快照内容与版本号都恢复原样**，
  因此回滚后再评估，结论与发布前逐字段一致。回滚只保留最近一次发布的前像。
- **旧结论不可再用**：存储额外维护单调递增的 `generation`，发布与回滚都会 +1，并计入评估缓存键。
  因此即使回滚到旧版本号，发布后/回滚前基于中间状态算出的缓存结论也不会再被复用。

### 限时临时例外

`POST /exceptions` 创建（`expiresAt` 必须晚于当前时间，否则当场 400 拒绝）：

```json
{"id": "ex-1", "scopePattern": "reg.example.com/team/**", "effect": "ALLOW",
 "priority": 10, "reason": "紧急放行", "expiresAt": "2026-10-09T00:00:00Z"}
```

规则：

- 在 `[创建时刻, expiresAt)` 内，命中作用域的最高优先级例外（优先级降序、同值按 id 升序）
  **覆盖正常策略判定**：`ALLOW` 豁免必需证据要求直接放行；`DENY` 即使证据齐备也显式拒绝
  （`denyReason=TEMPORARY_EXCEPTION_DENIED`）。
- 判定结论与审计记录新增 `appliedExceptionId` 字段：**能直接看出本次判定用到了哪个例外**；
  未使用例外时为 `null`。
- **到期自动失效**：到期后结论自动回到正常策略评估结果，不残留，
  更不会让该拒的镜像因过期例外被放行。
- **撤销立即失效**：`DELETE /exceptions/{id}` 不可逆；撤销后结论立即回到正常策略。
- 例外新增/撤销会推进例外存储版本号（计入缓存键）；缓存条目的失效时间同时取
  “证据最早到期”与“例外最早到期”的较早者，因此**例外一到期，旧的放行缓存立即不可再用**。
- 例外仍然建立在请求基本校验之上（镜像标识、摘要、标签漂移、证据摘要冲突等照旧校验）；
  作用域不命中的例外不产生任何效果。

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
  发布整体替换、版本号单调递增；每次评估只基于一个快照，并发发布不会出现半新半旧。
- **发布代次 generation**：发布与回滚都会让 `generation` 单调 +1。即使回滚恢复到旧版本号，
  代次仍不同——配合缓存键保证回滚后基于中间状态的旧结论不会再被使用。
- **缓存失效**：评估缓存键 = 镜像标识 + 解析摘要 + **策略版本** + **策略代次** +
  **例外版本** + **证据指纹**（证据 id/类型/摘要/格式版本/过期时间）。
  策略发布/回滚、例外新增/撤销或证据变化后旧键不再命中；缓存条目另带 `validUntil`，
  取“证据最早过期”与“例外最早到期”的较早者，任一到达后旧结论立即失效。
- **幂等与副作用**：同一缓存键的并发评估通过 `ConcurrentHashMap.compute` 只计算一次；
  审计以 `requestId` 为幂等键（`putIfAbsent`），同一镜像的并发或重复请求
  **只产生一条审计记录**。预演走静默评估，**不经过缓存与审计**。
- **可重现性**：输入、策略与例外均未变化时，重复评估结论一致（确定性排序 + 固定校验顺序）。
- **审计可还原**：每条审计记录包含镜像标识、策略版本、命中规则、证据 ID、判定解释
  以及 `appliedExceptionId`（用到例外时）；日志同步打印上述字段。

## 兼容性说明

- 对既有接入方**向后兼容**：原 `PUT /policies` 保留（语义等价于 stage+publish）；
  `EvaluationDecision` 仅在末尾**新增**可空字段 `appliedExceptionId`，旧消费方不受影响；
  既有 `denyReason` 取值不变，仅新增 `TEMPORARY_EXCEPTION_DENIED`。
- 新增的发布/回滚/预演/例外接口均为增量路径；不使用例外时，判定行为与旧版本一致。
- 回滚为单层：始终恢复到“最近一次发布”的发布前快照；无可回滚目标时返回 409，不做静默处理。
- 所有状态均为内存实现（含策略、例外、缓存、审计），进程重启后回到内置默认策略；
  预演与发布流程不依赖任何外部服务。

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
| `TEMPORARY_EXCEPTION_DENIED` | 命中有效期内的临时拒绝例外（结论中带 `appliedExceptionId`） |

## 本地验证方法

```bash
mvn test
```

测试覆盖（全部使用内存实现与固定/可拨动时钟，不依赖外部服务或真实凭据）：

- `ImageRefTest`（4 例）：镜像标识解析（含 registry 端口、非法输入）。
- `EvidenceValidatorTest`（5 例）：过期、未绑定、旧格式、不完整清单。
- `PolicyEngineTest`（3 例）：作用域 glob 匹配、优先级与同优先级确定性排序。
- `AdmissionServiceTest`（18 例）：正常准入、标签漂移、摘要冲突、过期/缺失/旧格式/
  不完整证据、策略冲突（DENY 优先）、无命中策略、重复评估确定性、策略更新使缓存失效、
  证据过期使缓存失效、新增证据改变结论、并发重复请求只产生一条审计、
  并发策略更新与评估的快照一致性、审计记录可还原策略版本/证据/命中规则。
  其中并发一致性用例的断言已对齐“每次评估整体来自某一个一致快照”的真实语义
  （v1 默认规则在带齐证据时本就 ALLOW，旧断言误把它当成失败，属于此前遗留的偶发失败）。
- `PolicyPreviewTest`（7 例，**预演业务**）：ALLOW→DENY 变化对比、同为 DENY 但原因变化、
  等价策略不变、预演不影响线上、预演不留审计/缓存副作用、非法候选策略可区分地当场拒绝、
  空输入拒绝。
- `PolicyReleaseTest`（8 例，**发布回滚业务**）：暂存不生效、非法候选无法暂存、
  无草稿/无回滚目标的错误、原子发布版本递增、回滚后结论与发布前逐字段一致、
  发布后及回滚后旧缓存结论不可再用、发布窗口内 12×200 次并发评估要么整体见旧要么整体见新。
- `TemporaryExceptionTest`（9 例，**限时例外业务**）：有效期 ALLOW 豁免证据且记录可见例外、
  DENY 即便证据齐备也拒绝、到期自动回到正常策略且记录不残留、撤销立即失效、
  撤销后旧缓存不可用、到期后旧缓存不放行、创建即无效/字段缺失被拒且不残留、
  作用域不命中不生效与多条例外高优先级胜出。
- **业务日志覆盖**：运行 `mvn test` 时，三个新业务测试类会在每个用例前打印
  `>>> [业务域:xxx] 执行用例: <DisplayName>`，汇总行形如
  `Tests run: 55, Failures: 0, Errors: 0, Skipped: 0`，可直接核对覆盖的业务与用例情况。
- `ApplicationTests`：Spring 上下文加载。

### 本地手工验证（curl）

启动后（`mvn spring-boot:run`）可按下面顺序手工验证“预演 → 发布 → 回滚 → 例外”：

```bash
# 1) 预演：候选策略对 team 作用域 DENY，观察 changed=true（不影响线上）
curl -s -XPOST localhost:8080/api/v1/admission/policies/preview \
  -H 'Content-Type: application/json' -d @preview.json

# 2) 暂存 + 发布
curl -s -XPOST localhost:8080/api/v1/admission/policies/stage \
  -H 'Content-Type: application/json' -d @candidate.json
curl -s -XPOST localhost:8080/api/v1/admission/policies/publish

# 3) 回滚到发布前
curl -s -XPOST localhost:8080/api/v1/admission/policies/rollback

# 4) 临时放行例外（24h 后到期）；到期/撤销后自动回到正常策略
curl -s -XPOST localhost:8080/api/v1/admission/exceptions \
  -H 'Content-Type: application/json' \
  -d '{"id":"ex-1","scopePattern":"reg.example.com/team/**","effect":"ALLOW",
       "priority":10,"reason":"紧急放行","expiresAt":"2026-10-09T00:00:00Z"}'
curl -s -XDELETE localhost:8080/api/v1/admission/exceptions/ex-1
```
