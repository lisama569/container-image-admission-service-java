package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdmissionServiceTest {

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final String OTHER_DIGEST = "sha256:" + "b".repeat(64);
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:1.0@" + DIGEST;

    private PolicyStore policyStore;
    private AuditLog auditLog;
    private AdmissionService service;

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        auditLog = new AuditLog();
        service = new AdmissionService(policyStore, new PolicyEngine(), new EvidenceValidator(), auditLog);
        service.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private Evidence evidence(String id, Evidence.EvidenceType type, String digest,
                              Instant expiresAt, int formatVersion, Map<String, String> attrs) {
        return new Evidence(id, type, digest, formatVersion, NOW.minusSeconds(3600), expiresAt, attrs);
    }

    /** 默认策略要求 VULN_SCAN + SIGNATURE 的有效证据。 */
    private List<Evidence> validEvidence() {
        return List.of(
                evidence("scan-1", Evidence.EvidenceType.VULN_SCAN, DIGEST, NOW.plusSeconds(3600), 2,
                        Map.of("scanner", "trivy", "criticalCount", "0")),
                evidence("sig-1", Evidence.EvidenceType.SIGNATURE, DIGEST, NOW.plusSeconds(3600), 2,
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
    }

    private EvaluationRequest request(String requestId, List<Evidence> evidence) {
        return new EvaluationRequest(requestId, IMAGE, DIGEST, evidence);
    }

    @Test
    void allowsWhenPolicyAndEvidenceSatisfied() {
        EvaluationDecision d = service.evaluate(request("req-allow", validEvidence()));
        assertEquals(EvaluationDecision.Verdict.ALLOW, d.verdict());
        assertEquals(1L, d.policyVersion());
        assertEquals(List.of("scan-1", "sig-1"), d.evidenceIds());
        assertEquals(List.of("default-require-scan-and-signature"), d.matchedRuleIds());
    }

    @Test
    void deniesMissingEvidence() {
        EvaluationDecision d = service.evaluate(request("req-missing",
                List.of(validEvidence().get(0))));
        assertEquals(EvaluationDecision.Verdict.DENY, d.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, d.denyReason());
    }

    @Test
    void deniesExpiredEvidence() {
        List<Evidence> ev = List.of(
                validEvidence().get(0),
                evidence("sig-old", Evidence.EvidenceType.SIGNATURE, DIGEST, NOW.minusSeconds(1), 2,
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
        EvaluationDecision d = service.evaluate(request("req-expired", ev));
        assertEquals(DenyReason.EVIDENCE_EXPIRED, d.denyReason());
    }

    @Test
    void deniesStaleFormatEvidence() {
        List<Evidence> ev = List.of(
                validEvidence().get(0),
                evidence("sig-v0", Evidence.EvidenceType.SIGNATURE, DIGEST, null, 0,
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
        EvaluationDecision d = service.evaluate(request("req-stale", ev));
        assertEquals(DenyReason.EVIDENCE_STALE_FORMAT, d.denyReason());
    }

    @Test
    void deniesIncompleteEvidence() {
        List<Evidence> ev = List.of(
                validEvidence().get(0),
                evidence("sig-inc", Evidence.EvidenceType.SIGNATURE, DIGEST, null, 2,
                        Map.of("signature", "abc"))); // 缺 publicKeyId
        EvaluationDecision d = service.evaluate(request("req-incomplete", ev));
        assertEquals(DenyReason.EVIDENCE_INCOMPLETE, d.denyReason());
    }

    @Test
    void deniesUnboundEvidence() {
        List<Evidence> ev = List.of(
                validEvidence().get(0),
                evidence("sig-other", Evidence.EvidenceType.SIGNATURE, OTHER_DIGEST, null, 2,
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
        // 证据绑定到其他摘要：与目标摘要冲突 → DIGEST_MISMATCH 优先于 UNBOUND
        EvaluationDecision d = service.evaluate(request("req-unbound", ev));
        assertEquals(DenyReason.DIGEST_MISMATCH, d.denyReason());
    }

    @Test
    void deniesTagDrift() {
        EvaluationRequest req = new EvaluationRequest("req-drift", IMAGE, OTHER_DIGEST, validEvidence());
        EvaluationDecision d = service.evaluate(req);
        assertEquals(DenyReason.TAG_DRIFT, d.denyReason());
    }

    @Test
    void deniesConflictingEvidenceDigests() {
        List<Evidence> ev = List.of(
                validEvidence().get(0),
                evidence("scan-2", Evidence.EvidenceType.VULN_SCAN, OTHER_DIGEST, null, 2,
                        Map.of("scanner", "trivy", "criticalCount", "0")));
        EvaluationDecision d = service.evaluate(request("req-conflict", ev));
        assertEquals(DenyReason.DIGEST_MISMATCH, d.denyReason());
    }

    @Test
    void deniesInvalidImageRef() {
        EvaluationRequest req = new EvaluationRequest("req-badref", "UPPER/Repo:tag", null, List.of());
        EvaluationDecision d = service.evaluate(req);
        assertEquals(DenyReason.INVALID_IMAGE_REF, d.denyReason());
    }

    @Test
    void deniesWhenNoPolicyApplies() {
        policyStore.update(List.of(new Policy("scoped", 1, List.of(
                new Policy.PolicyRule("prod-only", "prod.example.com/**", 0,
                        Policy.Effect.ALLOW, List.of())))));
        EvaluationDecision d = service.evaluate(request("req-noscope", validEvidence()));
        assertEquals(DenyReason.NO_APPLICABLE_POLICY, d.denyReason());
        assertEquals(2L, d.policyVersion());
    }

    @Test
    void explicitDenyRuleWinsByPriority() {
        policyStore.update(List.of(new Policy("mixed", 1, List.of(
                new Policy.PolicyRule("allow-all", "**", 1, Policy.Effect.ALLOW, List.of()),
                new Policy.PolicyRule("deny-team", "reg.example.com/team/**", 10,
                        Policy.Effect.DENY, List.of())))));
        EvaluationDecision d = service.evaluate(request("req-deny", validEvidence()));
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, d.denyReason());
        assertEquals(List.of("deny-team", "allow-all"), d.matchedRuleIds());
    }

    @Test
    void repeatedEvaluationIsDeterministic() {
        EvaluationDecision d1 = service.evaluate(request("req-det-1", validEvidence()));
        EvaluationDecision d2 = service.evaluate(request("req-det-2", validEvidence()));
        assertEquals(d1.verdict(), d2.verdict());
        assertEquals(d1.matchedRuleIds(), d2.matchedRuleIds());
        assertEquals(d1.evidenceIds(), d2.evidenceIds());
        assertEquals(d1.policyVersion(), d2.policyVersion());
    }

    @Test
    void policyUpdateInvalidatesCachedDecision() {
        EvaluationDecision before = service.evaluate(request("req-cache-1", validEvidence()));
        assertEquals(EvaluationDecision.Verdict.ALLOW, before.verdict());

        policyStore.update(List.of(new Policy("deny-all", 1, List.of(
                new Policy.PolicyRule("deny-all", "**", 100, Policy.Effect.DENY, List.of())))));

        EvaluationDecision after = service.evaluate(request("req-cache-2", validEvidence()));
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, after.denyReason());
        assertEquals(2L, after.policyVersion());
    }

    @Test
    void expiredEvidenceInvalidatesCachedDecision() {
        Instant expiry = NOW.plusSeconds(600);
        List<Evidence> ev = List.of(
                evidence("scan-1", Evidence.EvidenceType.VULN_SCAN, DIGEST, expiry, 2,
                        Map.of("scanner", "trivy", "criticalCount", "0")),
                evidence("sig-1", Evidence.EvidenceType.SIGNATURE, DIGEST, expiry, 2,
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
        EvaluationDecision before = service.evaluate(request("req-exp-1", ev));
        assertEquals(EvaluationDecision.Verdict.ALLOW, before.verdict());

        // 时钟前进到证据过期之后：同一请求不得再命中旧的 ALLOW 缓存
        AtomicLong tick = new AtomicLong(NOW.plusSeconds(601).toEpochMilli());
        service.setClock(Clock.fixed(Instant.ofEpochMilli(tick.get()), ZoneOffset.UTC));
        EvaluationDecision after = service.evaluate(request("req-exp-2", ev));
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.EVIDENCE_EXPIRED, after.denyReason());
    }

    @Test
    void newEvidenceChangesConclusion() {
        // 先因缺证据被拒绝，补充证据后同一镜像应放行
        EvaluationDecision denied = service.evaluate(request("req-ev-1",
                List.of(validEvidence().get(0))));
        assertEquals(DenyReason.MISSING_EVIDENCE, denied.denyReason());
        EvaluationDecision allowed = service.evaluate(request("req-ev-2", validEvidence()));
        assertEquals(EvaluationDecision.Verdict.ALLOW, allowed.verdict());
    }

    @Test
    void concurrentDuplicateRequestsProduceSingleAuditEntry() throws InterruptedException {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<EvaluationDecision> results = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    EvaluationDecision d = service.evaluate(request("req-dup", validEvidence()));
                    synchronized (results) {
                        results.add(d);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(threads, results.size());
        assertTrue(results.stream().allMatch(d -> d.verdict() == EvaluationDecision.Verdict.ALLOW));
        // 同一 requestId 的并发重复请求只产生一条审计记录
        assertEquals(1, auditLog.size());
    }

    @Test
    void concurrentPolicyUpdatesAndEvaluationsAreConsistent() throws InterruptedException {
        int threads = 8;
        int iterations = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<EvaluationDecision> results = new ArrayList<>();
        List<Throwable> errors = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            int worker = i;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < iterations; j++) {
                        if (worker % 2 == 0) {
                            // 一半线程并发更新策略
                            Policy.Effect effect = (j % 2 == 0) ? Policy.Effect.DENY : Policy.Effect.ALLOW;
                            policyStore.update(List.of(new Policy("p", 1, List.of(
                                    new Policy.PolicyRule("r", "**", 0, effect,
                                            effect == Policy.Effect.ALLOW
                                                    ? List.of(Evidence.EvidenceType.VULN_SCAN,
                                                    Evidence.EvidenceType.SIGNATURE)
                                                    : List.of())))));
                        } else {
                            EvaluationDecision d = service.evaluate(
                                    request("req-conc-" + worker + "-" + j, validEvidence()));
                            synchronized (results) {
                                results.add(d);
                            }
                        }
                    }
                } catch (Throwable t) {
                    synchronized (errors) {
                        errors.add(t);
                    }
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), "并发执行不应出错: " + errors);
        // 每条结论都必须基于某个一致的策略快照（版本号单调、结论可解释）
        for (EvaluationDecision d : results) {
            assertTrue(d.policyVersion() >= 1);
            if (d.verdict() == EvaluationDecision.Verdict.ALLOW) {
                assertEquals(List.of("r"), d.matchedRuleIds());
            } else {
                assertEquals(DenyReason.POLICY_EXPLICIT_DENY, d.denyReason());
            }
        }
    }

    @Test
    void auditEntryRestoresPolicyVersionEvidenceAndRules() {
        service.evaluate(request("req-audit", validEvidence()));
        assertEquals(1, auditLog.size());
        EvaluationDecision d = auditLog.entries().get(0).decision();
        assertEquals(1L, d.policyVersion());
        assertEquals(List.of("scan-1", "sig-1"), d.evidenceIds());
        assertEquals(List.of("default-require-scan-and-signature"), d.matchedRuleIds());
        assertEquals("reg.example.com/team/app:1.0@" + DIGEST, d.imageRef());
    }
}
