package com.github.lisama569.containerimageadmissionservicejava.service;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.ExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * 准入评估服务：编排策略快照、临时例外、证据校验、缓存与审计。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>每次评估只基于一个 {@link PolicySnapshot}；</li>
 *   <li>临时例外仅在未撤销、未到期、作用域命中时生效，结论中带 {@code appliedExceptionId}，
 *       到期/撤销后立即回到正常策略评估；</li>
 *   <li>缓存键包含策略版本、例外集合版本与证据指纹，策略/例外/证据变化后旧结论自动失效；
 *       命中例外的结论其 validUntil 不晚于例外到期时间；</li>
 *   <li>同一缓存键的并发评估通过 compute 只计算一次；</li>
 *   <li>审计按 requestId 幂等，重复请求不产生重复记录。</li>
 * </ul>
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final PolicyStore policyStore;
    private final PolicyEngine policyEngine;
    private final EvidenceValidator evidenceValidator;
    private final AuditLog auditLog;
    private final ExceptionStore exceptionStore;

    /** 内部评估产物：结论 + 该结论自身的失效时间（证据/例外最早到期）。 */
    private record EvaluateOutcome(EvaluationDecision decision, Instant validUntil) {
    }

    /** 缓存条目：validUntil 为证据/例外中最早的过期时间，到期后旧结论失效。 */
    private record CachedDecision(EvaluationDecision decision, Instant validUntil) {
    }

    private final ConcurrentMap<String, CachedDecision> cache = new ConcurrentHashMap<>();
    private volatile Clock clock = Clock.systemUTC();

    @Autowired
    public AdmissionService(PolicyStore policyStore, PolicyEngine policyEngine,
                            EvidenceValidator evidenceValidator, AuditLog auditLog,
                            ExceptionStore exceptionStore) {
        this.policyStore = policyStore;
        this.policyEngine = policyEngine;
        this.evidenceValidator = evidenceValidator;
        this.auditLog = auditLog;
        this.exceptionStore = exceptionStore;
    }

    /** 兼容无例外存储的构造方式（主要用于历史测试）。 */
    public AdmissionService(PolicyStore policyStore, PolicyEngine policyEngine,
                            EvidenceValidator evidenceValidator, AuditLog auditLog) {
        this(policyStore, policyEngine, evidenceValidator, auditLog, new ExceptionStore(new PolicyEngine()));
    }

    /** 测试用：注入固定时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /** 发布/回滚后调用：清空全部缓存，旧策略算出的结论不再被复用。 */
    public void invalidateCache() {
        cache.clear();
    }

    public EvaluationDecision evaluate(EvaluationRequest request) {
        // 缓存键包含策略版本、例外集合版本与证据指纹：任一变化后旧结论不再命中
        PolicySnapshot snapshot = policyStore.snapshot();
        String cacheKey = cacheKey(request, snapshot.version());
        Instant now = clock.instant();
        CachedDecision entry = cache.compute(cacheKey, (k, existing) -> {
            // 证据/例外已到期（失效）的缓存结论不得继续生效
            if (existing != null && (existing.validUntil() == null || now.isBefore(existing.validUntil()))) {
                return existing;
            }
            EvaluateOutcome outcome = doEvaluate(request, snapshot);
            return new CachedDecision(outcome.decision(), outcome.validUntil());
        });
        auditLog.record(request.requestId(), entry.decision());
        return entry.decision();
    }

    /**
     * 按指定快照评估，不走缓存、不写审计。供预演使用：
     * 预演只是看结果，不能影响线上判定，也不能留下正式判定记录。
     */
    public EvaluationDecision evaluateWith(EvaluationRequest request, PolicySnapshot snapshot) {
        return doEvaluate(request, snapshot).decision();
    }

    private EvaluateOutcome doEvaluate(EvaluationRequest request, PolicySnapshot snapshot) {
        long policyVersion = snapshot.version();
        Instant now = clock.instant();

        // 1. 请求基本校验
        if (request.requestId() == null || request.requestId().isBlank()) {
            return deny(DenyReason.INVALID_REQUEST, request.imageRef(), policyVersion,
                    "requestId 缺失");
        }
        // 2. 镜像标识解析
        ImageRef image;
        try {
            image = ImageRef.parse(request.imageRef());
        } catch (IllegalArgumentException e) {
            return deny(DenyReason.INVALID_IMAGE_REF, request.imageRef(), policyVersion,
                    "镜像标识非法: " + e.getMessage());
        }
        String canonical = image.canonical();

        // 3. 确定有效摘要
        String effectiveDigest = image.digest() != null ? image.digest() : request.resolvedDigest();
        if (effectiveDigest == null || effectiveDigest.isBlank()) {
            return deny(DenyReason.INVALID_REQUEST, canonical, policyVersion,
                    "缺少镜像摘要，无法绑定证据");
        }
        // 4. 标签漂移：请求摘要与仓库当前解析摘要不一致
        if (image.digest() != null && request.resolvedDigest() != null
                && !image.digest().equals(request.resolvedDigest())) {
            return deny(DenyReason.TAG_DRIFT, canonical, policyVersion,
                    "标签当前解析摘要 " + request.resolvedDigest() + " 与请求摘要 " + image.digest() + " 不一致");
        }
        // 5. 证据摘要互相冲突
        List<Evidence> evidenceList = request.evidenceList() != null ? request.evidenceList() : List.of();
        Set<String> distinctDigests = evidenceList.stream()
                .map(Evidence::imageDigest)
                .filter(d -> d != null && !d.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (distinctDigests.size() > 1) {
            return deny(DenyReason.DIGEST_MISMATCH, canonical, policyVersion,
                    "证据绑定的摘要互相冲突: " + distinctDigests);
        }

        // 6. 策略作用域解析
        List<Policy.PolicyRule> matched = policyEngine.matchRules(snapshot, image);
        List<String> matchedRuleIds = matched.stream().map(Policy.PolicyRule::ruleId).toList();

        // 7. 临时例外：未撤销、未到期且作用域命中时按例外放行。
        //    例外是策略层面的覆盖（含无命中策略/显式拒绝/证据不足），
        //    但不覆盖镜像身份与请求完整性问题（2~5 步）。
        Optional<TemporaryException> exception = exceptionStore.activeExceptionFor(image);
        if (exception.isPresent()) {
            TemporaryException ex = exception.get();
            EvaluationDecision decision = EvaluationDecision.allow(canonical, policyVersion,
                    matchedRuleIds, List.of(),
                    "临时例外 " + ex.id() + " 在有效期内（至 " + ex.expiresAt()
                            + "）覆盖正常策略评估" + (ex.reason() != null ? "：" + ex.reason() : ""),
                    ex.id());
            log.info("admission image={} verdict=ALLOW policyVersion={} exception={} expiresAt={} matchedRules={}",
                    canonical, policyVersion, ex.id(), ex.expiresAt(), matchedRuleIds);
            return new EvaluateOutcome(decision, ex.expiresAt());
        }

        if (matched.isEmpty()) {
            return deny(DenyReason.NO_APPLICABLE_POLICY, canonical, policyVersion,
                    "没有命中任何策略规则，默认拒绝");
        }

        // 8. 冲突处理：排序后第一条规则的效果生效
        Policy.PolicyRule winner = matched.get(0);
        if (winner.effect() == Policy.Effect.DENY) {
            return new EvaluateOutcome(EvaluationDecision.deny(DenyReason.POLICY_EXPLICIT_DENY,
                    canonical, policyVersion,
                    matchedRuleIds, List.of(),
                    "命中显式拒绝规则 " + winner.ruleId()), earliestExpiry(request));
        }

        // 9. 证据校验：收集所需类型，缺失时区分原因
        List<Evidence> valid = evidenceValidator.validEvidence(evidenceList, effectiveDigest, now);
        Set<Evidence.EvidenceType> validTypes = valid.stream().map(Evidence::type).collect(Collectors.toSet());
        List<Evidence.EvidenceType> required = winner.requiredEvidence() != null
                ? winner.requiredEvidence() : List.of();
        List<Evidence.EvidenceType> missing = new ArrayList<>();
        for (Evidence.EvidenceType type : required) {
            if (!validTypes.contains(type)) {
                missing.add(type);
            }
        }
        if (!missing.isEmpty()) {
            // 若存在该类型但无效的证据，报告其具体无效原因；否则报告缺失
            DenyReason reason = DenyReason.MISSING_EVIDENCE;
            String detail = "缺少必需证据类型 " + missing;
            for (Evidence.EvidenceType type : missing) {
                DenyReason invalid = evidenceList.stream()
                        .filter(e -> e.type() == type)
                        .map(e -> evidenceValidator.validate(e, effectiveDigest, now))
                        .filter(r -> r != null)
                        .min(Comparator.comparingInt(Enum::ordinal))
                        .orElse(null);
                if (invalid != null) {
                    reason = invalid;
                    detail = "证据类型 " + type + " 存在但无效: " + invalid;
                    break;
                }
            }
            return new EvaluateOutcome(EvaluationDecision.deny(reason, canonical,
                    policyVersion, matchedRuleIds,
                    evidenceList.stream().map(Evidence::id).toList(), detail), earliestExpiry(request));
        }

        // 10. 准入
        List<String> evidenceIds = valid.stream().map(Evidence::id).sorted().toList();
        EvaluationDecision decision = EvaluationDecision.allow(canonical, policyVersion,
                matchedRuleIds, evidenceIds,
                "命中规则 " + winner.ruleId() + "，必需证据齐备");
        log.info("admission image={} verdict=ALLOW policyVersion={} matchedRules={} evidence={}",
                canonical, policyVersion, matchedRuleIds, evidenceIds);
        return new EvaluateOutcome(decision, earliestExpiry(request));
    }

    /** 证据中最早的过期时间；无过期时间返回 null（不过期）。 */
    private Instant earliestExpiry(EvaluationRequest request) {
        if (request.evidenceList() == null) {
            return null;
        }
        return request.evidenceList().stream()
                .map(Evidence::expiresAt)
                .filter(e -> e != null)
                .min(Instant::compareTo)
                .orElse(null);
    }

    private EvaluateOutcome deny(DenyReason reason, String imageRef, long policyVersion, String detail) {
        log.info("admission image={} verdict=DENY reason={} policyVersion={} detail={}",
                imageRef, reason, policyVersion, detail);
        return new EvaluateOutcome(EvaluationDecision.deny(reason, imageRef, policyVersion,
                List.of(), List.of(), detail), null);
    }

    /** 缓存键：镜像 + 解析摘要 + 策略版本 + 例外集合版本 + 证据指纹。 */
    private String cacheKey(EvaluationRequest request, long policyVersion) {
        List<Evidence> evidenceList = request.evidenceList() != null ? request.evidenceList() : List.of();
        String fingerprint = evidenceList.stream()
                .map(e -> String.join("|", String.valueOf(e.id()), String.valueOf(e.type()),
                        String.valueOf(e.imageDigest()), String.valueOf(e.formatVersion()),
                        String.valueOf(e.expiresAt())))
                .sorted()
                .collect(Collectors.joining(";"));
        return String.join("#", String.valueOf(request.imageRef()),
                String.valueOf(request.resolvedDigest()),
                String.valueOf(policyVersion),
                String.valueOf(exceptionStore.version()),
                fingerprint);
    }
}
