package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.TemporaryExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyReleaseService;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidationException;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域：候选策略受控发布与回滚。
 * 用例：暂存不生效、原子发布版本递增、并发发布窗口内评估只整体见旧/新快照、
 * 回滚后结论与发布前逐字段一致、发布/回滚后旧缓存结论不可再用、非法候选无法暂存。
 */
@DisplayName("业务域：受控发布与整体回滚（原子切换，不留中间态）")
class PolicyReleaseTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyReleaseTest.class);

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:1.0@" + DIGEST;

    private PolicyStore policyStore;
    private PolicyReleaseService release;
    private AdmissionService admission;
    private AuditLog auditLog;

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        auditLog = new AuditLog();
        TemporaryExceptionStore exceptionStore = new TemporaryExceptionStore();
        exceptionStore.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        admission = new AdmissionService(policyStore, new PolicyEngine(),
                new EvidenceValidator(), auditLog, exceptionStore);
        admission.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        release = new PolicyReleaseService(policyStore,
                new com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidator());
    }

    @BeforeEach
    void logCase(TestInfo info) {
        log.info(">>> [业务域:受控发布与回滚] 执行用例: {}", info.getDisplayName());
    }

    private List<Evidence> validEvidence() {
        return List.of(
                new Evidence("scan-1", Evidence.EvidenceType.VULN_SCAN, DIGEST, 2,
                        NOW.minusSeconds(3600), NOW.plusSeconds(3600),
                        Map.of("scanner", "trivy", "criticalCount", "0")),
                new Evidence("sig-1", Evidence.EvidenceType.SIGNATURE, DIGEST, 2,
                        NOW.minusSeconds(3600), NOW.plusSeconds(3600),
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
    }

    private EvaluationRequest request(String id) {
        return new EvaluationRequest(id, IMAGE, DIGEST, validEvidence());
    }

    /** 显式拒绝一切的候选策略。 */
    private List<Policy> denyAllCandidate() {
        return List.of(new Policy("deny-all", 2, List.of(
                new Policy.PolicyRule("deny-all", "**", 100, Policy.Effect.DENY, List.of()))));
    }

    @Test
    @DisplayName("发布：暂存不影响线上，发布后原子生效，版本递增")
    void stageThenPublish() {
        EvaluationDecision before = admission.evaluate(request("r-before"));
        assertEquals(EvaluationDecision.Verdict.ALLOW, before.verdict());

        long draft = release.stage(denyAllCandidate());
        assertEquals(2L, draft);
        // 暂存后线上仍旧：带齐证据仍 ALLOW，版本仍 1
        EvaluationDecision staged = admission.evaluate(request("r-staged"));
        assertEquals(EvaluationDecision.Verdict.ALLOW, staged.verdict());
        assertEquals(1L, staged.policyVersion());

        long publishedVersion = release.publish();
        assertEquals(2L, publishedVersion);
        EvaluationDecision after = admission.evaluate(request("r-after"));
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, after.denyReason());
        assertEquals(2L, after.policyVersion());
        assertFalse(release.hasStaged(), "发布后草稿应清空");
        log.info("[发布] v1 ALLOW -> v2 DENY，暂存期间线上保持 v1");
    }

    @Test
    @DisplayName("发布：非法候选策略无法暂存，更不可能上线")
    void invalidCandidateCannotStage() {
        List<Policy> bad = List.of(new Policy("p", 2, List.of())); // 无规则
        assertThrows(PolicyValidationException.class, () -> release.stage(bad));
        assertFalse(release.hasStaged());
        // 线上未受影响
        assertEquals(EvaluationDecision.Verdict.ALLOW,
                admission.evaluate(request("r-bad-stage")).verdict());
    }

    @Test
    @DisplayName("发布：没有草稿时发布被拒绝")
    void publishWithoutStageRejected() {
        assertThrows(IllegalStateException.class, () -> release.publish());
    }

    @Test
    @DisplayName("回滚：整体回到发布前，结论与发布前一模一样")
    void rollbackRestoresPriorSnapshotExactly() {
        EvaluationDecision pre = admission.evaluate(request("r-pre"));

        release.stage(denyAllCandidate());
        release.publish();
        EvaluationDecision mid = admission.evaluate(request("r-mid"));
        assertEquals(EvaluationDecision.Verdict.DENY, mid.verdict());

        long restoredVersion = release.rollback();
        assertEquals(1L, restoredVersion, "回滚后版本号恢复为发布前版本");
        EvaluationDecision post = admission.evaluate(request("r-post"));

        // 结论必须与发布前逐字段一致
        assertEquals(pre.verdict(), post.verdict());
        assertEquals(pre.denyReason(), post.denyReason());
        assertEquals(pre.policyVersion(), post.policyVersion());
        assertEquals(pre.matchedRuleIds(), post.matchedRuleIds());
        assertEquals(pre.evidenceIds(), post.evidenceIds());
        assertEquals(EvaluationDecision.Verdict.ALLOW, post.verdict());
        log.info("[回滚] 恢复到 v{}，结论与发布前一致 verdict={} rules={} evidence={}",
                post.policyVersion(), post.verdict(), post.matchedRuleIds(), post.evidenceIds());
    }

    @Test
    @DisplayName("回滚：没有可回滚目标时被拒绝")
    void rollbackWithoutPublishRejected() {
        assertThrows(IllegalStateException.class, () -> release.rollback());
    }

    @Test
    @DisplayName("回滚：回滚前基于中间策略算出的结论回滚后不得再被使用")
    void cachedIntermediateDecisionInvalidAfterRollback() {
        release.stage(denyAllCandidate());
        release.publish();
        EvaluationDecision mid = admission.evaluate(request("r-mid-cached"));
        assertEquals(EvaluationDecision.Verdict.DENY, mid.verdict());

        release.rollback();
        // 同一镜像（新 requestId，相同输入）回滚后必须重新得到 v1 的 ALLOW，
        // 而不是复用回滚前缓存下的 DENY
        EvaluationDecision post = admission.evaluate(request("r-mid-cached-post"));
        assertEquals(EvaluationDecision.Verdict.ALLOW, post.verdict());
        assertEquals(1L, post.policyVersion());
    }

    @Test
    @DisplayName("发布：发布后基于旧策略的缓存结论不得再被使用")
    void oldCachedDecisionInvalidAfterPublish() {
        EvaluationDecision pre = admission.evaluate(request("r-old-cache"));
        assertEquals(EvaluationDecision.Verdict.ALLOW, pre.verdict());

        release.stage(denyAllCandidate());
        release.publish();
        EvaluationDecision post = admission.evaluate(request("r-old-cache-post"));
        assertEquals(EvaluationDecision.Verdict.DENY, post.verdict());
        assertEquals(2L, post.policyVersion());
    }

    @Test
    @DisplayName("并发：发布进行中的评估要么整体用发布前、要么整体用发布后，绝不混用")
    void concurrentEvaluationsSeeConsistentSnapshotDuringPublish() throws InterruptedException {
        int evaluators = 12;
        int perEvaluator = 200;
        ExecutorService pool = Executors.newFixedThreadPool(evaluators + 1);
        CountDownLatch evaluatorsReady = new CountDownLatch(evaluators);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger seq = new AtomicInteger();
        List<EvaluationDecision> decisions = new ArrayList<>();
        List<Throwable> errors = new ArrayList<>();

        for (int i = 0; i < evaluators; i++) {
            pool.submit(() -> {
                try {
                    evaluatorsReady.countDown();
                    start.await();
                    for (int j = 0; j < perEvaluator; j++) {
                        EvaluationDecision d = admission.evaluate(
                                request("r-conc-" + seq.incrementAndGet()));
                        synchronized (decisions) {
                            decisions.add(d);
                        }
                    }
                } catch (Throwable t) {
                    synchronized (errors) {
                        errors.add(t);
                    }
                }
            });
        }
        // 发布线程：等评估线程都就绪后，在它们密集评估期间发布
        pool.submit(() -> {
            try {
                evaluatorsReady.await();
                start.countDown();
                release.stage(denyAllCandidate());
                release.publish();
            } catch (Throwable t) {
                synchronized (errors) {
                    errors.add(t);
                }
            }
        });

        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), "并发发布/评估不应出错: " + errors);
        assertEquals(evaluators * perEvaluator, decisions.size());

        int preCount = 0;
        int postCount = 0;
        for (EvaluationDecision d : decisions) {
            if (d.policyVersion() == 1L) {
                // 发布前快照：default 规则，带齐证据 → ALLOW
                preCount++;
                assertEquals(EvaluationDecision.Verdict.ALLOW, d.verdict());
                assertEquals(List.of("default-require-scan-and-signature"), d.matchedRuleIds(),
                        "同一次评估不得混用两个快照的规则");
            } else if (d.policyVersion() == 2L) {
                // 发布后快照：deny-all 规则 → DENY
                postCount++;
                assertEquals(EvaluationDecision.Verdict.DENY, d.verdict());
                assertEquals(DenyReason.POLICY_EXPLICIT_DENY, d.denyReason());
                assertEquals(List.of("deny-all"), d.matchedRuleIds(),
                        "同一次评估不得混用两个快照的规则");
            } else {
                throw new AssertionError("出现非预期版本: " + d.policyVersion());
            }
        }
        log.info("[并发发布] 共 {} 次评估：整体见发布前 {} 次，整体见发布后 {} 次，无混用",
                decisions.size(), preCount, postCount);
        // 评估与发布高度重叠时，两侧通常都会观测到；即便极端调度只见到一侧，也必须全部自洽
        assertTrue(preCount + postCount == decisions.size());
    }
}
