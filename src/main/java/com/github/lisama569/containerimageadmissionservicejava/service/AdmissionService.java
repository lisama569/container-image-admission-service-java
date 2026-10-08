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
import com.github.lisama569.containerimageadmissionservicejava.exception.TemporaryExceptionStore;
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
 *   <li>缓存键包含策略版本、策略代次（generation）、例外版本与证据指纹，
 *       策略发布/回滚、例外新增/撤销或证据变化后旧结论自动失效；
 *       缓存条目的 validUntil 同时受证据与例外最早到期时间约束，
 *       例外一到期旧的放行结论立即不可再用；</li>
 *   <li>同一缓存键的并发评估通过 computeIfAbsent 只计算一次；</li>
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
    private final TemporaryExceptionStore exceptionStore;
    /** 缓存条目：validUntil 为证据/例外中最早的过期时间，到期后旧结论失效。 */
    private record CachedDecision(EvaluationDecision decision, Instant validUntil) {
    }

    private final ConcurrentMap<String, CachedDecision> cache = new ConcurrentHashMap<>();
    private volatile Clock clock = Clock.systemUTC();

    @Autowired
    public AdmissionService(PolicyStore policyStore, PolicyEngine policyEngine,
                            EvidenceValidator evidenceValidator, AuditLog auditLog,
                            TemporaryExceptionStore exceptionStore) {
        this.policyStore = policyStore;
        this.policyEngine = policyEngine;
        this.evidenceValidator = evidenceValidator;
        this.auditLog = auditLog;
        this.exceptionStore = exceptionStore;
    }

    /** 兼容无例外存储的装配方式（单元测试使用）。 */
    public AdmissionService(PolicyStore policyStore, PolicyEngine policyEngine,
                            EvidenceValidator evidenceValidator, AuditLog auditLog) {
        this(policyStore, policyEngine, evidenceValidator, auditLog, null);
    }

    /** 测试用：注入固定时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    public EvaluationDecision evaluate(EvaluationRequest request) {
        // 缓存键包含策略版本/代次、例外版本与证据指纹：发布、回滚、例外变化或证据变化后旧结论不再命中
        PolicySnapshot snapshot = policyStore.snapshot();
        String cacheKey = cacheKey(request, snapshot.version());
        Instant now = clock.instant();
        CachedDecision entry = cache.compute(cacheKey, (k, existing) -> {
            // 证据或例外已过期（失效）的缓存结论不得继续生效
            if (existing != null && (existing.validUntil() == null || now.isBefore(existing.validUntil()))) {
                return existing;
            }
            return new CachedDecision(doEvaluate(request, snapshot), entryValidUntil(request, now));
        });
        auditLog.record(request.requestId(), entry.decision());
        return entry.decision();
    }

    /**
     * 静默评估：基于任意策略快照计算结论，但<strong>不</strong>读/写缓存、<strong>不</strong>写审计。
     * 专供候选策略预演使用——预演只是看结果，不能影响线上判定，也不能留下正式判定记录。
     */
    public EvaluationDecision evaluateSilently(EvaluationRequest request, PolicySnapshot snapshot) {
        return doEvaluate(request, snapshot);
    }

    private EvaluationDecision doEvaluate(EvaluationRequest request, PolicySnapshot snapshot) {
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

        // 6. 策略作用域解析（即便后续被例外覆盖，也保留命中规则便于解释）
        List<Policy.PolicyRule> matched = policyEngine.matchRules(snapshot, image);
        List<String> matchedRuleIds = matched.stream().map(Policy.PolicyRule::ruleId).toList();

        // 7. 临时例外：有效期内命中的最高优先级例外覆盖正常策略判定；
        //    过期/撤销/创建即无效的例外不会出现在 activeAt 中，绝不残留。
        TemporaryException applied = activeException(image, now);
        if (applied != null) {
            return applyException(applied, image, canonical, policyVersion,
                    matchedRuleIds, evidenceList, effectiveDigest, now);
        }

        // 8. 无例外时，没有命中任何策略规则默认拒绝
        if (matched.isEmpty()) {
            return deny(DenyReason.NO_APPLICABLE_POLICY, canonical, policyVersion,
                    "没有命中任何策略规则，默认拒绝");
        }

        // 9. 冲突处理：排序后第一条规则的效果生效
        Policy.PolicyRule winner = matched.get(0);
        if (winner.effect() == Policy.Effect.DENY) {
            return new EvaluationDecision(EvaluationDecision.Verdict.DENY,
                    DenyReason.POLICY_EXPLICIT_DENY, canonical, policyVersion,
                    matchedRuleIds, List.of(),
                    "命中显式拒绝规则 " + winner.ruleId(), null);
        }

        // 10. 证据校验：收集所需类型，缺失时区分原因
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
            return new EvaluationDecision(EvaluationDecision.Verdict.DENY, reason, canonical,
                    policyVersion, matchedRuleIds,
                    evidenceList.stream().map(Evidence::id).toList(), detail, null);
        }

        // 11. 准入
        List<String> evidenceIds = valid.stream().map(Evidence::id).sorted().toList();
        EvaluationDecision decision = EvaluationDecision.allow(canonical, policyVersion,
                matchedRuleIds, evidenceIds,
                "命中规则 " + winner.ruleId() + "，必需证据齐备");
        log.info("admission image={} verdict=ALLOW policyVersion={} matchedRules={} evidence={}",
                canonical, policyVersion, matchedRuleIds, evidenceIds);
        return decision;
    }

    /** 找到当前时刻有效且作用域命中的最高优先级例外；无则 null。 */
    private TemporaryException activeException(ImageRef image, Instant now) {
        if (exceptionStore == null) {
            return null;
        }
        return exceptionStore.activeAt(now).stream()
                .filter(e -> policyEngine.scopeMatches(e.scopePattern(), image))
                .findFirst()
                .orElse(null);
    }

    /** 按例外产出结论：ALLOW 例外豁免证据要求，DENY 例外显式拒绝。 */
    private EvaluationDecision applyException(TemporaryException exception, ImageRef image,
                                              String canonical, long policyVersion,
                                              List<String> matchedRuleIds, List<Evidence> evidenceList,
                                              String effectiveDigest, Instant now) {
        String digest = image.digest() != null ? image.digest() : effectiveDigest;
        if (exception.effect() == Policy.Effect.DENY) {
            log.info("admission image={} verdict=DENY reason=TEMPORARY_EXCEPTION_DENIED "
                            + "policyVersion={} exceptionId={} expiresAt={}",
                    canonical, policyVersion, exception.id(), exception.expiresAt());
            return EvaluationDecision.deny(DenyReason.TEMPORARY_EXCEPTION_DENIED, canonical,
                    policyVersion, matchedRuleIds, List.of(),
                    "命中临时拒绝例外 " + exception.id()
                            + (exception.reason() != null ? "（" + exception.reason() + "）" : "")
                            + "，到期时间 " + exception.expiresAt(),
                    exception.id());
        }
        // ALLOW 例外：豁免该作用域的必需证据要求；仍如实记录已有有效证据
        List<String> evidenceIds = evidenceValidator
                .validEvidence(evidenceList, digest, now).stream()
                .map(Evidence::id).sorted().toList();
        log.info("admission image={} verdict=ALLOW policyVersion={} exceptionId={} expiresAt={} "
                        + "matchedRules={} evidence={}",
                canonical, policyVersion, exception.id(), exception.expiresAt(),
                matchedRuleIds, evidenceIds);
        return EvaluationDecision.allow(canonical, policyVersion, matchedRuleIds, evidenceIds,
                "命中临时放行例外 " + exception.id()
                        + (exception.reason() != null ? "（" + exception.reason() + "）" : "")
                        + "，豁免证据要求，到期时间 " + exception.expiresAt(),
                exception.id());
    }

    /** 缓存条目失效时间：证据最早到期与例外最早到期取较早者。 */
    private Instant entryValidUntil(EvaluationRequest request, Instant now) {
        Instant evidenceExpiry = earliestExpiry(request);
        Instant exceptionExpiry = exceptionStore != null
                ? exceptionStore.earliestExpiry(now) : null;
        if (evidenceExpiry == null) {
            return exceptionExpiry;
        }
        if (exceptionExpiry == null) {
            return evidenceExpiry;
        }
        return evidenceExpiry.isBefore(exceptionExpiry) ? evidenceExpiry : exceptionExpiry;
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

    private EvaluationDecision deny(DenyReason reason, String imageRef, long policyVersion, String detail) {
        log.info("admission image={} verdict=DENY reason={} policyVersion={} detail={}",
                imageRef, reason, policyVersion, detail);
        return EvaluationDecision.deny(reason, imageRef, policyVersion,
                List.of(), List.of(), detail);
    }

    /** 缓存键：镜像 + 解析摘要 + 策略版本 + 策略代次 + 例外版本 + 证据指纹。 */
    private String cacheKey(EvaluationRequest request, long policyVersion) {
        List<Evidence> evidenceList = request.evidenceList() != null ? request.evidenceList() : List.of();
        String fingerprint = evidenceList.stream()
                .map(e -> String.join("|", String.valueOf(e.id()), String.valueOf(e.type()),
                        String.valueOf(e.imageDigest()), String.valueOf(e.formatVersion()),
                        String.valueOf(e.expiresAt())))
                .sorted()
                .collect(Collectors.joining(";"));
        long generation = policyStore.generation();
        long exceptionVersion = exceptionStore != null ? exceptionStore.version() : 0L;
        return String.join("#", String.valueOf(request.imageRef()),
                String.valueOf(request.resolvedDigest()),
                String.valueOf(policyVersion),
                String.valueOf(generation),
                String.valueOf(exceptionVersion),
                fingerprint);
    }
}
