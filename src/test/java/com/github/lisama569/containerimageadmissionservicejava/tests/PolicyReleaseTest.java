package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.ExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.exception.InvalidCandidatePolicyException;
import com.github.lisama569.containerimageadmissionservicejava.policy.CandidatePolicyValidator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import com.github.lisama569.containerimageadmissionservicejava.service.ReleaseService;
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
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 受控发布与整体回滚业务场景测试：原子切换、并发一致性、回滚后结论一致、旧结论不复用。
 */
class PolicyReleaseTest {

    private static final String DIGEST = "sha256:" + "c".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:2.0@" + DIGEST;

    private PolicyStore policyStore;
    private AuditLog auditLog;
    private AdmissionService admissionService;
    private ReleaseService releaseService;
    private final ScenarioLogger scenario = ScenarioLogger.of(getClass());

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        PolicyEngine engine = new PolicyEngine();
        auditLog = new AuditLog();
        ExceptionStore exceptionStore = new ExceptionStore(engine);
        admissionService = new AdmissionService(policyStore, engine, new EvidenceValidator(),
                auditLog, exceptionStore);
        admissionService.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        releaseService = new ReleaseService(policyStore, new CandidatePolicyValidator(),
                admissionService);
    }

    private List<Evidence> fullEvidence() {
        return List.of(
                new Evidence("scan-1", Evidence.EvidenceType.VULN_SCAN, DIGEST, 2,
                        NOW.minusSeconds(3600), NOW.plusSeconds(3600),
                        Map.of("scanner", "trivy", "criticalCount", "0")),
                new Evidence("sig-1", Evidence.EvidenceType.SIGNATURE, DIGEST, 2,
                        NOW.minusSeconds(3600), NOW.plusSeconds(3600),
                        Map.of("signature", "abc", "publicKeyId", "key-1")));
    }

    private EvaluationRequest request(String id) {
        return new EvaluationRequest(id, IMAGE, DIGEST, fullEvidence());
    }

    private Policy denyAllPolicy() {
        return new Policy("deny-all", 1, List.of(
                new Policy.PolicyRule("deny-all", "**", 100, Policy.Effect.DENY, List.of())));
    }

    @Test
    void stagedCandidateDoesNotAffectLiveAndPublishSwitchesAtomically() {
        scenario.scenario("发布-暂存不生效，发布后原子切换");
        EvaluationDecision before = admissionService.evaluate(request("rel-before"));
        scenario.casee("发布前评估", "ALLOW@v1");
        assertEquals(EvaluationDecision.Verdict.ALLOW, before.verdict());
        assertEquals(1L, before.policyVersion());

        String label = releaseService.stage(List.of(denyAllPolicy()));
        scenario.casee("暂存全拒绝候选 " + label, "线上仍为 v1，暂存不影响判定");
        EvaluationDecision whileStaged = admissionService.evaluate(request("rel-staged"));
        assertEquals(1L, whileStaged.policyVersion());
        assertEquals(EvaluationDecision.Verdict.ALLOW, whileStaged.verdict());

        long newVersion = releaseService.publish();
        scenario.casee("发布", "版本变为 2，评估整体切换为 DENY");
        assertEquals(2L, newVersion);
        EvaluationDecision after = admissionService.evaluate(request("rel-after"));
        assertEquals(2L, after.policyVersion());
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, after.denyReason());
        scenario.summary("暂存与线上隔离，发布是一次整体切换");
    }

    @Test
    void rollbackRestoresExactPrePublishConclusionAndVersionAdvances() {
        scenario.scenario("回滚-结论与发布前一模一样，且旧结论不被复用");
        EvaluationDecision pre = admissionService.evaluate(request("rb-pre"));
        scenario.casee("发布前结论", "ALLOW@v1, 规则 default-require-scan-and-signature");
        assertEquals(List.of("default-require-scan-and-signature"), pre.matchedRuleIds());

        releaseService.stage(List.of(denyAllPolicy()));
        long published = releaseService.publish();
        EvaluationDecision during = admissionService.evaluate(request("rb-during"));
        scenario.casee("发布后", "DENY@" + published);
        assertEquals(EvaluationDecision.Verdict.DENY, during.verdict());

        long rolledBack = releaseService.rollback();
        scenario.casee("回滚", "新版本号 " + rolledBack + " 单调递增（>发布版本），策略内容恢复");
        assertTrue(rolledBack > published, "回滚版本号必须继续递增，保证旧缓存键失效");

        EvaluationDecision post = admissionService.evaluate(request("rb-post"));
        scenario.casee("回滚后再评估", "结论与发布前一模一样：ALLOW + 相同命中规则 + 相同证据");
        assertEquals(EvaluationDecision.Verdict.ALLOW, post.verdict());
        assertEquals(rolledBack, post.policyVersion());
        assertEquals(pre.matchedRuleIds(), post.matchedRuleIds());
        assertEquals(pre.evidenceIds(), post.evidenceIds());
        assertEquals(pre.denyReason(), post.denyReason());
        scenario.summary("回滚后策略内容完全恢复；版本号变化确保发布期旧结论无法复用");
    }

    @Test
    void concurrentEvaluationsDuringPublishSeeExactlyOneConsistentSnapshot() throws Exception {
        scenario.scenario("并发发布-进行中的评估要么全用发布前、要么全用发布后");
        int evaluatorThreads = 12;
        int perThread = 200;
        ExecutorService pool = Executors.newFixedThreadPool(evaluatorThreads + 1);
        CountDownLatch ready = new CountDownLatch(evaluatorThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(evaluatorThreads);
        // 每次评估记录 (版本号, 结论, 命中规则)：同一评估内部不得出现版本与规则错配
        List<EvaluationDecision> decisions = java.util.Collections.synchronizedList(new ArrayList<>());
        AtomicReference<Throwable> error = new AtomicReference<>();

        for (int t = 0; t < evaluatorThreads; t++) {
            int worker = t;
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        EvaluationDecision d = admissionService.evaluate(
                                request("conc-" + worker + "-" + i));
                        decisions.add(d);
                    }
                } catch (Throwable e) {
                    error.compareAndSet(null, e);
                } finally {
                    done.countDown();
                }
            });
        }
        // 发布线程与所有评估线程同时开闸
        Future<?> publisher = pool.submit(() -> {
            try {
                ready.countDown();
                start.await();
                releaseService.stage(List.of(denyAllPolicy()));
                releaseService.publish();
            } catch (Throwable e) {
                error.compareAndSet(null, e);
            }
        });

        assertTrue(ready.await(10, TimeUnit.SECONDS), "工作线程未能全部就绪");
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        publisher.get(30, TimeUnit.SECONDS);
        pool.shutdown();

        scenario.casee("并发 " + evaluatorThreads + "x" + perThread + " 评估与 1 次发布同时进行",
                "每条结论的 (版本,规则) 必须自洽：v1↔默认规则，v2↔deny-all，不允许混用");
        assertEquals(null, error.get(),
                error.get() == null ? "并发执行不应出错" : error.get().toString());
        long allowV1 = 0;
        long denyV2 = 0;
        for (EvaluationDecision d : decisions) {
            if (d.policyVersion() == 1L) {
                // 发布前快照：证据齐备 -> ALLOW，命中默认规则
                assertEquals(EvaluationDecision.Verdict.ALLOW, d.verdict(),
                        "v1 快照下结论必须一致，不能混入新策略影响: " + d);
                assertEquals(List.of("default-require-scan-and-signature"), d.matchedRuleIds(),
                        "v1 评估不得命中发布后规则: " + d);
                allowV1++;
            } else if (d.policyVersion() == 2L) {
                // 发布后快照：显式 DENY
                assertEquals(EvaluationDecision.Verdict.DENY, d.verdict(),
                        "v2 快照下结论必须一致: " + d);
                assertEquals(DenyReason.POLICY_EXPLICIT_DENY, d.denyReason());
                assertEquals(List.of("deny-all"), d.matchedRuleIds(),
                        "v2 评估必须整体使用新规则，不得残留旧规则: " + d);
                denyV2++;
            } else {
                throw new AssertionError("出现非预期版本: " + d.policyVersion());
            }
        }
        scenario.casee("统计两侧结果",
                "v1-ALLOW=" + allowV1 + "，v2-DENY=" + denyV2 + "，合计=" + decisions.size());
        assertEquals(evaluatorThreads * perThread, allowV1 + denyV2);
        assertTrue(allowV1 > 0, "应当存在发布前完成的评估");
        assertTrue(denyV2 > 0, "应当存在发布后完成的评估");
        scenario.summary("发布进行中不存在半新半旧：每条评估整体属于发布前或发布后快照");
    }

    @Test
    void failedPublishKeepsLiveUntouchedAndStagingInvalidCandidateRejected() {
        scenario.scenario("发布失败-线上不受影响，可整体回退");
        // 暂存一份非法候选：发布前校验就应拒绝，且没有暂存内容
        Policy invalid = new Policy("bad", 1, List.of());
        assertThrows(InvalidCandidatePolicyException.class,
                () -> releaseService.stage(List.of(invalid)));
        scenario.casee("暂存非法候选", "当场抛 InvalidCandidatePolicyException，线上不变");
        assertThrows(InvalidCandidatePolicyException.class, releaseService::publish);
        scenario.casee("无暂存时发布", "被拒绝，线上仍为 v1");
        assertEquals(1L, policyStore.snapshot().version());
        assertEquals(EvaluationDecision.Verdict.ALLOW,
                admissionService.evaluate(request("rel-fail-live")).verdict());

        // 发布一个合法候选后，再发布（暂存已清空）应失败，但不清空/不动当前线上
        releaseService.stage(List.of(denyAllPolicy()));
        releaseService.publish();
        assertThrows(InvalidCandidatePolicyException.class, releaseService::publish);
        scenario.casee("发布成功后再次发布（无候选）", "失败且线上保持 v2 的 DENY");
        assertEquals(2L, policyStore.snapshot().version());
        assertEquals(EvaluationDecision.Verdict.DENY,
                admissionService.evaluate(request("rel-fail-live2")).verdict());
        scenario.summary("任何发布失败都不产生中间状态，线上结论保持确定");
    }
}
