package com.github.lisama569.containerimageadmissionservicejava.tests;

import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.attestation;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.constraints;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.image;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.manifest;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.policy;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.sbom;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.scopeAll;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.signature;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.vulnScan;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditService;
import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.DecisionOutcome;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReasonCode;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationInput;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect;
import com.github.lisama569.containerimageadmissionservicejava.domain.Severity;
import com.github.lisama569.containerimageadmissionservicejava.eval.AdmissionCache;
import com.github.lisama569.containerimageadmissionservicejava.eval.DigestNormalizer;
import com.github.lisama569.containerimageadmissionservicejava.eval.EvidenceFingerprint;
import com.github.lisama569.containerimageadmissionservicejava.eval.PolicyEvaluator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.ScopeMatcher;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;

class AdmissionServiceTest {

    private final AuditService auditService = new AuditService(TestFixtures.FIXED_CLOCK);
    private final AdmissionCache cache = new AdmissionCache();
    private final PolicyStore policyStore = new PolicyStore(TestFixtures.FIXED_CLOCK, cache);
    private final PolicyEvaluator evaluator = new PolicyEvaluator(
            new ScopeMatcher(), new DigestNormalizer(), TestFixtures.FIXED_CLOCK);
    private final AdmissionService service = new AdmissionService(
            policyStore, evaluator, cache, auditService, new EvidenceFingerprint(), new DigestNormalizer());

    private PolicyDefinition strictPolicy(int version) {
        return policy("strict", version, 100, scopeAll(), List.of(
                new PolicyRule("r1", "严格", 100, RuleEffect.ALLOW,
                        constraints(true, true, Severity.HIGH, true,
                                List.of("ci-bot"), List.of("slsa/provenance")))));
    }

    private EvaluationInput fullInput() {
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 2),
                signature("sig-1", TestFixtures.DIGEST, "ci-bot",
                        TestFixtures.NOW.plusSeconds(3600), 1),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
        return new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST), ev);
    }

    @Test
    void duplicateRequestIdIsIdempotentWithSingleAudit() {
        policyStore.put("strict", strictPolicy(1));
        AdmissionResult first = service.evaluate(fullInput(), "req-1");
        AdmissionResult second = service.evaluate(fullInput(), "req-1");
        assertThat(first.decision()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(second).isSameAs(first);
        assertThat(auditService.size()).isEqualTo(1);
        assertThat(auditService.findByRequestId("req-1")).isPresent();
    }

    @Test
    void samePayloadDifferentRequestSharesCache() {
        policyStore.put("strict", strictPolicy(1));
        AdmissionResult r1 = service.evaluate(fullInput(), "req-a");
        AdmissionResult r2 = service.evaluate(fullInput(), "req-b");
        assertThat(r1.cacheKey()).isEqualTo(r2.cacheKey());
        assertThat(cache.size()).isEqualTo(1);
        assertThat(auditService.size()).isEqualTo(2);
    }

    @Test
    void addedEvidenceChangesFingerprintAndInvalidatesOldConclusion() {
        policyStore.put("strict", strictPolicy(1));
        // 初始证据不足（只有 sbom）→ 拒绝
        EvaluationInput insufficient = new EvaluationInput(image(TestFixtures.DIGEST),
                manifest(TestFixtures.DIGEST),
                List.of(sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo"))));
        AdmissionResult denied = service.evaluate(insufficient, "req-deny");
        assertThat(denied.decision()).isEqualTo(DecisionOutcome.DENY);
        // 补齐证据后（新 requestId）→ 允许，缓存键不同
        AdmissionResult allowed = service.evaluate(fullInput(), "req-allow");
        assertThat(allowed.decision()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(allowed.cacheKey()).isNotEqualTo(denied.cacheKey());
    }

    @Test
    void expiredEvidenceFlipsDecision() {
        policyStore.put("strict", strictPolicy(1));
        AdmissionResult ok = service.evaluate(fullInput(), "req-ok");
        assertThat(ok.decision()).isEqualTo(DecisionOutcome.ALLOW);

        List<Evidence> expiredEv = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 2),
                signature("sig-1", TestFixtures.DIGEST, "ci-bot",
                        TestFixtures.NOW.minusSeconds(1), 1),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
        AdmissionResult expired = service.evaluate(
                new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST), expiredEv),
                "req-expired");
        assertThat(expired.decision()).isEqualTo(DecisionOutcome.DENY);
        assertThat(expired.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.SIGNATURE_EXPIRED);
        assertThat(expired.cacheKey()).isNotEqualTo(ok.cacheKey());
    }

    @Test
    void policyChangeInvalidatesCachedConclusion() {
        policyStore.put("strict", strictPolicy(1));
        AdmissionResult r1 = service.evaluate(fullInput(), "req-v1");
        assertThat(r1.decision()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(cache.size()).isEqualTo(1);

        // 收紧策略：v2 只信任另一个签名者
        PolicyDefinition v2 = policy("strict", 2, 100, scopeAll(), List.of(
                new PolicyRule("r1", "严格v2", 100, RuleEffect.ALLOW,
                        constraints(true, true, Severity.HIGH, true,
                                List.of("other-team"), List.of("slsa/provenance")))));
        policyStore.put("strict", v2);
        assertThat(cache.size()).isZero();

        AdmissionResult r2 = service.evaluate(fullInput(), "req-v2");
        assertThat(r2.decision()).isEqualTo(DecisionOutcome.DENY);
        assertThat(r2.policySnapshotVersion()).isGreaterThan(r1.policySnapshotVersion());
        assertThat(r2.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.SIGNATURE_UNTRUSTED_SIGNER);
    }

    @Test
    void concurrentSameRequestIdProducesSingleAudit() throws Exception {
        policyStore.put("strict", strictPolicy(1));
        int n = 20;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger sameRefCount = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AdmissionResult r = service.evaluate(fullInput(), "concurrent-req");
                    if (r.decision() == DecisionOutcome.ALLOW) {
                        sameRefCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        assertThat(sameRefCount.get()).isEqualTo(n);
        assertThat(auditService.size()).isEqualTo(1);
    }
}
