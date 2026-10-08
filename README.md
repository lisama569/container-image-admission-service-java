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
| POST | `/api/v1/admission/rehearse` | **预演**：候选策略对一批请求的结论对比，不影响线上、不留判定记录 |
| POST | `/api/v1/admission/policies/stage` | 暂存候选策略（先校验，不生效） |
| POST | `/api/v1/admission/policies/publish` | **受控发布**：已暂存候选原子切到线上 |
| POST | `/api/v1/admission/policies/rollback` | **整体回滚**：恢复发布前策略（版本号继续递增） |
| GET  | `/api/v1/admission/policies` | 查看当前策略快照（含版本号） |
| PUT  | `/api/v1/admission/policies` | 原子替换全部策略，版本号递增（旧快照保留可回滚） |
| POST | `/api/v1/admission/exceptions` | 创建带到期时间的临时例外 |
| DELETE | `/api/v1/admission/exceptions/{id}` | 撤销临时例外 |
| GET  | `/api/v1/admission/exceptions` | 查看未撤销例外（含已到期，到期者不再生效） |
| GET  | `/api/v1/admission/audit`    | 查看审计记录 |

## 预演（先看结果，不碰线上）

拿一份**尚未生效**的候选策略，对指定的一批镜像做“如果按这份策略判”的对比：

```json
POST /api/v1/admission/rehearse
{
  "policies": [
    {"name": "candidate", "version": 1, "rules": [
      {"ruleId": "cand-deny-all", "scopePattern": "**", "priority": 0,
       "effect": "DENY", "requiredEvidence": []}]}
  ],
  "requests": [ { "...": "与 /evaluate 相同的评估请求" } ]
}
```

返回 `RehearsalReport`：

- `currentVersion`：当前线上版本；`candidateLabel`：候选标识（**候选不分配线上版本号**，
  候选侧结论的 `policyVersion` 标记为负数，避免与正式结论混淆）。
- `changes[]`：结论发生变化的镜像，每项含 `before`/`after` 两份完整结论，
  直接回答“哪些镜像会变、从什么变成什么”（含 verdict、denyReason、命中规则）。
- `unchanged[]`：结论不变的镜像引用。

规则与边界：

- 预演只读线上快照做基线、用候选做对照；**不读写评估缓存、不产生审计记录、不改变线上判定**。
- 候选策略先经结构校验（列表非空、name/ruleId 非空且不重复、scope/effect 必填、
  requiredEvidence 类型非空且不重复、每条策略至少一条规则）。不合法时返回
  **HTTP 400 + `errorType=INVALID_CANDIDATE_POLICY` + 全部问题列表**，
  与镜像准入的 `denyReason`（HTTP 422）和普通参数错误（`INVALID_ARGUMENT`）明确区分，绝不悄悄放过。
- 临时例外对基线/候选两侧同时生效（例外独立于策略版本），因此报告差异只反映策略本身变化。
- 判定结论“是否变化”按 `verdict + denyReason` 比较；命中规则变化但最终结论不变的镜像归入 unchanged。

## 受控发布与整体回滚

流程：`stage`（校验+暂存，不生效）→ 可先 `rehearse` 预演确认 → `publish`（原子切换）→
需要时 `rollback`（整体回退）。

- **原子切换，无中间态**：发布/回滚在同一把锁上整体替换不可变快照引用
  （`PolicyStore.snapshot()` 读路径无锁）。发布进行中并发过来的评估，
  要么整体使用发布前快照，要么整体使用发布后快照，不会出现规则混用。
- **版本号始终单调递增**：发布与回滚都产生新版本号（回滚不是把版本号改回去）。
  评估缓存键含策略版本，因此发布/回滚后基于旧版本算出的结论不可能再被命中；
  切换成功后还会主动清空一次评估缓存，双保险。
- **回滚后结论与发布前一模一样**：回滚恢复发布前同一份策略内容；
  在相同输入下重新评估，verdict/denyReason/命中规则/证据结论与发布前完全一致。
- **失败不留半成品**：候选不合法、没有暂存内容等情况下发布被拒绝，
  线上快照与缓存都不会被改动（HTTP 400 `INVALID_CANDIDATE_POLICY` / HTTP 409 `ILLEGAL_STATE`）。
- 兼容：原有 `PUT /policies` 保留，语义等价于“直接暂存并发布”，同样保留旧快照可回滚。

## 限时临时例外

对指定镜像或范围设置**必须带到期时间**的例外，例如：

```json
POST /api/v1/admission/exceptions
{"id": "ex-hotfix-1", "scopePattern": "reg.example.com/team/**",
 "effect": "ALLOW", "expiresAt": "2026-10-09T00:00:00Z", "reason": "紧急修复窗口"}
```

- 作用域 glob 与策略规则同一套匹配语义；多个有效例外命中同一镜像时，**最早到期者**生效（再按 id 去重），结果确定。
- 例外是**策略层面的覆盖**：在“镜像身份/请求完整性校验通过”的前提下，
  有效期内无论正常策略结论是显式拒绝、证据不足还是无命中策略，均按例外放行。
  但 `INVALID_REQUEST`/`INVALID_IMAGE_REF`/`TAG_DRIFT`/`DIGEST_MISMATCH`
  这类身份与完整性问题不被例外覆盖。
- **判定记录可识别**：例外放行的结论 `appliedExceptionId` 带例外 ID，解释文本含到期时间与理由；
  审计记录同样包含该字段（日志也会打印 `exception=... expiresAt=...`）。
- **到期自动回落**：每次评估按当前时钟检查有效期，到期即查不到该例外，
  结论自动回到正常策略评估；命中例外的缓存结论其失效时间不晚于例外到期时间，
  到期后旧的放行缓存不会继续命中。
- **撤销立即生效**：`DELETE /exceptions/{id}` 物理移除例外，后续评估立即回到正常策略。
- **过期/无效不残留、不放行**：创建时 `expiresAt` 缺失或不晚于当前时间、id/作用域/效果缺失、
  id 重复都会被当场拒绝（HTTP 400 `INVALID_ARGUMENT`）；
  已到期的例外不会把“本应拒绝”的镜像放过去。


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
  受控发布/回滚在同一把锁内切换引用，进行中的并发评估整体属于发布前或发布后快照。
- **缓存失效**：评估缓存键 = 镜像标识 + 解析摘要 + **策略版本** + **例外集合版本** + **证据指纹**
  （证据 id/类型/摘要/格式版本/过期时间）。策略发布/回滚、例外新增/撤销或证据新增/变更后旧键不再命中；
  发布/回滚成功后还会主动清空缓存。缓存条目另带 `validUntil`
  （证据最早过期时间与命中例外到期时间的较早者），证据或例外到期后旧结论不得继续生效。
- **幂等与副作用**：同一缓存键的并发评估通过 `ConcurrentHashMap.compute` 只计算一次；
  审计以 `requestId` 为幂等键（`putIfAbsent`），同一镜像的并发或重复请求
  **只产生一条审计记录**。预演走独立入口（`evaluateWith`），**不读不写缓存、不写审计**。
- **可重现性**：输入与策略均未变化时，重复评估结论一致（确定性排序 + 固定校验顺序）。
- **审计可还原**：每条审计记录包含镜像标识、策略版本、命中规则、证据 ID、
  命中的临时例外 ID 与判定解释；日志同步打印上述字段。

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

> 注：`denyReason` 是**镜像准入结论**（HTTP 422）。候选策略本身填错属于另一类错误，
> 预演/暂存/发布时返回 HTTP 400 `errorType=INVALID_CANDIDATE_POLICY`（附全部问题）；
> 例外非法同为 HTTP 400 `INVALID_ARGUMENT`；无可回滚快照/无暂存候选为 HTTP 409
> `ILLEGAL_STATE`。三类错误互不混淆。

## 本地验证方法

```bash
mvn test
```

测试覆盖（全部使用内存实现与固定时钟，不依赖外部服务或真实凭据；
`src/test/resources/logback-test.xml` 让 `mvn test` 日志按“业务场景 / 用例 / 结论”打印覆盖情况）：

- `ImageRefTest`（4 例）：镜像标识解析（含 registry 端口、非法输入）。
- `EvidenceValidatorTest`（5 例）：过期、未绑定、旧格式、不完整清单。
- `PolicyEngineTest`（3 例）：作用域 glob 匹配、优先级与同优先级确定性排序。
- `AdmissionServiceTest`（18 例）：正常准入、标签漂移、摘要冲突、过期/缺失/旧格式/
  不完整证据、策略冲突（DENY 优先）、无命中策略、重复评估确定性、策略更新使缓存失效、
  证据过期使缓存失效、新增证据改变结论、并发重复请求只产生一条审计、
  并发策略更新与评估的快照一致性（含修复初始默认策略下 ALLOW 的合法断言）、
  审计记录可还原策略版本/证据/命中规则。
- `RehearsalServiceTest`（4 例，**新增预演场景**）：
  ALLOW→DENY 变化检测（含前后结论与原因）、DENY→ALLOW 与不变镜像分流、
  预演不影响线上判定且不留审计记录、候选策略非法时分类报错（ruleId 重复/无规则/空列表）且无副作用。
- `PolicyReleaseTest`（4 例，**新增并发发布与回滚场景**）：
  暂存不生效与发布原子切换、回滚后结论与发布前完全一致且版本单调递增、
  **12 线程×200 次评估与 1 次发布并发**时每条结论的（版本,规则）整体自洽无混用、
  发布失败（非法候选/无暂存）线上不受影响。
- `TemporaryExceptionTest`（6 例，**新增限时例外交替场景**）：
  有效期内覆盖正常策略且结论/审计可见 `appliedExceptionId`、作用域不越界、
  到期自动回到正常策略（含显式 DENY 下过期例外不放行）、撤销立即失效、
  例外放行缓存到期后失效、创建非法例外（空作用域/已过期/缺 expiresAt/id 重复）被拒。
- `ApplicationTests`：Spring 上下文加载（覆盖新组件的依赖装配）。

## 本地手工验证（HTTP 流程）

启动服务后可按“预演 → 暂存 → 发布 → 回滚”顺序手工验证：

```bash
# 1) 预演一份“全拒绝”候选（线上不变）
curl -s -X POST localhost:8080/api/v1/admission/rehearse \
  -H 'Content-Type: application/json' -d '{"policies":[{"name":"c","version":1,"rules":[
    {"ruleId":"d","scopePattern":"**","priority":0,"effect":"DENY","requiredEvidence":[]}]}],
    "requests":[]}'

# 2) 暂存 -> 发布 -> 回滚
curl -s -X POST localhost:8080/api/v1/admission/policies/stage -H 'Content-Type: application/json' -d '[ ...同上 policies... ]'
curl -s -X POST localhost:8080/api/v1/admission/policies/publish
curl -s -X POST localhost:8080/api/v1/admission/policies/rollback

# 3) 临时例外：创建 / 撤销 / 查看
curl -s -X POST localhost:8080/api/v1/admission/exceptions -H 'Content-Type: application/json' \
  -d '{"id":"ex-1","scopePattern":"reg.example.com/team/**","effect":"ALLOW",
       "expiresAt":"2026-10-09T00:00:00Z","reason":"hotfix"}'
curl -s -X DELETE localhost:8080/api/v1/admission/exceptions/ex-1
```
