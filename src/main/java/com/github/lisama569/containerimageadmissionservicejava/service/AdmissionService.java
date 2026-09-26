package com.github.lisama569.containerimageadmissionservicejava.service;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditRecord;
import com.github.lisama569.containerimageadmissionservicejava.audit.AuditService;
import com.github.lisama569.containerimageadmissionservicejava.common.ApiException;
import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationInput;
import com.github.lisama569.containerimageadmissionservicejava.eval.AdmissionCache;
import com.github.lisama569.containerimageadmissionservicejava.eval.DigestNormalizer;
import com.github.lisama569.containerimageadmissionservicejava.eval.EvidenceFingerprint;
import com.github.lisama569.containerimageadmissionservicejava.eval.PolicyEvaluator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;

/**
 * 准入评估编排：
 *
 * <ul>
 *   <li>评估开始时获取一个不可变 {@link PolicySnapshot}，整次评估只使用它；</li>
 *   <li>缓存键 = 策略快照版本 + 归一化摘要 + 证据指纹，任何输入/策略变化都会改变键，
 *       策略变更时存储层还会整体失效缓存，杜绝旧结论复用；</li>
 *   <li>同一 requestId 的并发请求通过 per-key 锁合并为一次真实评估与一次审计写入；</li>
 *   <li>幂等：重复 requestId 直接返回首次审计记录中的结论。</li>
 * </ul>
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final PolicyStore policyStore;
    private final PolicyEvaluator evaluator;
    private final AdmissionCache cache;
    private final AuditService auditService;
    private final EvidenceFingerprint fingerprint;
    private final DigestNormalizer digestNormalizer;

    /** 正在评估中的 requestId → 锁对象，用于合并并发重复请求。 */
    private final ConcurrentHashMap<String, Object> inFlight = new ConcurrentHashMap<>();

    public AdmissionService(PolicyStore policyStore, PolicyEvaluator evaluator, AdmissionCache cache,
                            AuditService auditService, EvidenceFingerprint fingerprint,
                            DigestNormalizer digestNormalizer) {
        this.policyStore = policyStore;
        this.evaluator = evaluator;
        this.cache = cache;
        this.auditService = auditService;
        this.fingerprint = fingerprint;
        this.digestNormalizer = digestNormalizer;
    }

    public AdmissionResult evaluate(EvaluationInput input, String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new ApiException("INPUT_INVALID: requestId 不能为空");
        }
        Optional<AuditRecord> existing = auditService.findByRequestId(requestId);
        if (existing.isPresent()) {
            AdmissionResult r = existing.get().result();
            log.info("重复请求命中已审计结论 requestId={} image={} policySnapshot={} decision={} fromCache=IDEMPOTENT",
                    requestId, r.imageReference(), r.policySnapshotVersion(), r.decision());
            return r;
        }
        Object lock = inFlight.computeIfAbsent(requestId, k -> new Object());
        try {
            synchronized (lock) {
                // 双检：可能在等待锁期间已由另一线程完成
                Optional<AuditRecord> raced = auditService.findByRequestId(requestId);
                if (raced.isPresent()) {
                    AdmissionResult r = raced.get().result();
                    log.info("并发重复请求合并到已有结论 requestId={} image={} policySnapshot={} decision= {}",
                            requestId, r.imageReference(), r.policySnapshotVersion(), r.decision());
                    return r;
                }
                AdmissionResult result = doEvaluate(input);
                auditService.recordOnce(requestId, result.imageReference(), result.digest(),
                        result.policySnapshotVersion(), result);
                return result;
            }
        } finally {
            inFlight.remove(requestId, lock);
        }
    }

    private AdmissionResult doEvaluate(EvaluationInput input) {
        // 先取一致快照；快照版本参与缓存键
        PolicySnapshot snapshot = policyStore.snapshot();
        String digest = normalizedDigestOrBlank(input);
        String evidenceFp = fingerprint.fingerprint(input.evidences());
        String cacheKey = "v" + snapshot.snapshotVersion() + "|" + digest + "|" + evidenceFp;

        Optional<AdmissionResult> cached = cache.get(cacheKey);
        if (cached.isPresent()) {
            log.info("评估命中缓存 image={} policySnapshot={} 证据指纹={} decision={}",
                    input.image() == null ? "<unknown>" : input.image().reference(),
                    snapshot.snapshotVersion(), evidenceFp, cached.get().decision());
            return cached.get();
        }
        AdmissionResult result = evaluator.evaluate(input, snapshot, cacheKey, false);
        cache.put(cacheKey, result);
        return result;
    }

    private String normalizedDigestOrBlank(EvaluationInput input) {
        if (input == null || input.image() == null || input.image().digest() == null
                || input.image().digest().isBlank()) {
            return "";
        }
        try {
            return digestNormalizer.normalize(input.image().digest());
        } catch (IllegalArgumentException ex) {
            return input.image().digest();
        }
    }

    public AuditRecord getAudit(String requestId) {
        return auditService.findByRequestId(requestId)
                .orElseThrow(() -> new ApiException("审计记录不存在: " + requestId));
    }
}
