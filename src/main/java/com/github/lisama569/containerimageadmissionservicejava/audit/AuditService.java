package com.github.lisama569.containerimageadmissionservicejava.audit;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;

/**
 * 审计存储（内存实现）。
 *
 * <p>幂等保证：以 requestId 为键，{@code computeIfAbsent} 保证同一 requestId
 * 的并发或重复请求只写入一条审计记录，不产生重复副作用。
 * 审计记录完整保存准入结论（含命中规则、证据 id、策略快照版本），可还原判定依据。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final ConcurrentHashMap<String, AuditRecord> byRequestId = new ConcurrentHashMap<>();
    private final Clock clock;

    public AuditService(Clock clock) {
        this.clock = clock;
    }

    /** 幂等写入：同一 requestId 只记录一次。 */
    public AuditRecord recordOnce(String requestId, String imageReference, String digest,
                                  long policySnapshotVersion, AdmissionResult result) {
        return byRequestId.computeIfAbsent(requestId, rid -> {
            AuditRecord rec = new AuditRecord(
                    UUID.randomUUID().toString(), rid, imageReference, digest,
                    policySnapshotVersion, result, Instant.now(clock));
            log.info("写入审计 recordId={} requestId={} image={} digest={} policySnapshot={} decision={} 规则={} 证据={}",
                    rec.id(), rid, imageReference, digest, policySnapshotVersion, result.decision(),
                    result.ruleHits().stream()
                            .map(h -> h.policyName() + "/" + h.ruleId() + "(" + h.effect() + ")")
                            .toList(),
                    result.evidenceIds());
            return rec;
        });
    }

    public Optional<AuditRecord> findByRequestId(String requestId) {
        return Optional.ofNullable(byRequestId.get(requestId));
    }

    public List<AuditRecord> findByImage(String digest) {
        return byRequestId.values().stream()
                .filter(r -> digest.equals(r.digest()))
                .sorted(Comparator.comparing(AuditRecord::recordedAt))
                .toList();
    }

    public List<AuditRecord> list() {
        return byRequestId.values().stream()
                .sorted(Comparator.comparing(AuditRecord::recordedAt))
                .toList();
    }

    public int size() {
        return byRequestId.size();
    }
}
