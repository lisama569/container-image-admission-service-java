package com.github.lisama569.containerimageadmissionservicejava.audit;

import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 审计日志：幂等记录，可还原策略版本、证据与判定依据。
 *
 * <p>以 requestId 作为幂等键：同一 requestId 的并发或重复请求
 * 只会产生一条审计记录（{@link ConcurrentHashMap#putIfAbsent} 保证）。
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    public record AuditEntry(String requestId, EvaluationDecision decision) {
    }

    private final ConcurrentMap<String, EvaluationDecision> entries = new ConcurrentHashMap<>();

    /**
     * 幂等追加：同一 requestId 只记录一次。
     *
     * @return true 表示本次实际写入
     */
    public boolean record(String requestId, EvaluationDecision decision) {
        boolean written = entries.putIfAbsent(requestId, decision) == null;
        if (written) {
            log.info("audit image={} verdict={} reason={} policyVersion={} matchedRules={} evidence={} requestId={}",
                    decision.imageRef(), decision.verdict(), decision.denyReason(),
                    decision.policyVersion(), decision.matchedRuleIds(),
                    decision.evidenceIds(), requestId);
        }
        return written;
    }

    public List<AuditEntry> entries() {
        return entries.entrySet().stream()
                .map(e -> new AuditEntry(e.getKey(), e.getValue()))
                .toList();
    }

    public int size() {
        return entries.size();
    }
}
