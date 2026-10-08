package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PreviewItem;
import com.github.lisama569.containerimageadmissionservicejava.domain.PreviewReport;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.TemporaryExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidationException;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidator;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import com.github.lisama569.containerimageadmissionservicejava.service.PolicyPreviewService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域：候选策略预演。
 * 用例：结论变化对比（含拒绝原因变化）、预演不影响线上、预演不留正式审计记录、
 * 非法候选策略可区分地当场拒绝、空输入拒绝。
 */
@DisplayName("业务域：候选策略预演（先看结果，不碰线上）")
class PolicyPreviewTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyPreviewTest.class);

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:1.0@" + DIGEST;

    private PolicyStore policyStore;
    private AuditLog auditLog;
    private AdmissionService admission;
    private PolicyPreviewService preview;
    private TemporaryExceptionStore exceptionStore;

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        auditLog = new AuditLog();
        exceptionStore = new TemporaryExceptionStore();
        exceptionStore.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        admission = new AdmissionService(policyStore, new PolicyEngine(),
                new EvidenceValidator(), auditLog, exceptionStore);
        admission.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        preview = new PolicyPreviewService(admission, policyStore, new PolicyValidator());
    }

    @BeforeEach
    void logCase(TestInfo info) {
        log.info(">>> [业务域:候选策略预演] 执行用例: {}", info.getDisplayName());
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

    private EvaluationRequest target(String id, List<Evidence> evidence) {
        return new EvaluationRequest(id, IMAGE, DIGEST, evidence);
    }

    /** 候选策略：对 team 作用域显式 DENY。 */
    private List<Policy> denyTeamCandidate() {
        return List.of(new Policy("candidate", 2, List.of(
                new Policy.PolicyRule("candidate-deny-team", "reg.example.com/team/**", 100,
                        Policy.Effect.DENY, List.of()))));
    }

    @Test
    @DisplayName("预演：带齐证据时从 ALLOW 变为 DENY，报告里能看出从什么变成什么")
    void showsAllowToDenyChange() {
        PreviewReport report = preview.preview(denyTeamCandidate(),
                List.of(target("t1", validEvidence())));

        assertEquals(1L, report.currentVersion());
        assertEquals(0L, report.candidateVersion(), "候选草稿版本号应为 0（尚未生效）");
        assertEquals(1, report.items().size());
        PreviewItem item = report.items().get(0);
        assertEquals(EvaluationDecision.Verdict.ALLOW, item.currentVerdict());
        assertEquals(EvaluationDecision.Verdict.DENY, item.candidateVerdict());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, item.candidateReason());
        assertTrue(item.changed(), "结论从 ALLOW 变 DENY 必须标记 changed");
        log.info("[预演-结论变化] {} -> {} (原因 {})，changed={}",
                item.currentVerdict(), item.candidateVerdict(), item.candidateReason(), item.changed());
    }

    @Test
    @DisplayName("预演：同为 DENY 但拒绝原因变化也算变化（缺证据 → 显式拒绝）")
    void denyReasonChangeDetected() {
        // 不带证据：当前默认策略 ALLOW 规则下缺证据 → MISSING_EVIDENCE；
        // 候选显式 DENY → POLICY_EXPLICIT_DENY。verdict 同为 DENY，但原因变了。
        PreviewReport report = preview.preview(denyTeamCandidate(),
                List.of(target("t2", List.of())));
        PreviewItem item = report.items().get(0);
        assertEquals(EvaluationDecision.Verdict.DENY, item.currentVerdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, item.currentReason());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, item.candidateReason());
        assertTrue(item.changed());
    }

    @Test
    @DisplayName("预演：等价策略下结论不变")
    void equivalentCandidateMarksUnchanged() {
        // 候选与默认策略等价：** ALLOW 且要求 VULN_SCAN + SIGNATURE
        List<Policy> same = List.of(new Policy("same", 2, List.of(
                new Policy.PolicyRule("default-require-scan-and-signature", "**", 0,
                        Policy.Effect.ALLOW,
                        List.of(Evidence.EvidenceType.VULN_SCAN, Evidence.EvidenceType.SIGNATURE)))));
        PreviewReport report = preview.preview(same, List.of(target("t3", validEvidence())));
        PreviewItem item = report.items().get(0);
        assertFalse(item.changed());
        assertEquals(EvaluationDecision.Verdict.ALLOW, item.candidateVerdict());
    }

    @Test
    @DisplayName("预演：只看结果，不影响线上判定")
    void previewDoesNotChangeLivePolicy() {
        preview.preview(denyTeamCandidate(), List.of(target("t4", validEvidence())));

        // 预演后线上仍是 v1 默认策略：带齐证据照常 ALLOW，且策略版本仍为 1
        EvaluationDecision live = admission.evaluate(
                new EvaluationRequest("live-1", IMAGE, DIGEST, validEvidence()));
        assertEquals(EvaluationDecision.Verdict.ALLOW, live.verdict());
        assertEquals(1L, live.policyVersion());
        assertEquals(List.of("default-require-scan-and-signature"), live.matchedRuleIds());
    }

    @Test
    @DisplayName("预演：不留下正式判定记录（无审计、无缓存副作用）")
    void previewLeavesNoAuditRecord() {
        preview.preview(denyTeamCandidate(),
                List.of(target("t5", validEvidence()), target("t6", validEvidence())));
        assertEquals(0, auditLog.size(), "预演不得写审计日志");

        // 预演后首次真实评估仍是新鲜计算（不命中预演的任何缓存内容），产生唯一审计
        EvaluationDecision live = admission.evaluate(
                new EvaluationRequest("live-audit", IMAGE, DIGEST, validEvidence()));
        assertEquals(EvaluationDecision.Verdict.ALLOW, live.verdict());
        assertEquals(1, auditLog.size(), "只有真实评估产生一条审计");
    }

    @Test
    @DisplayName("预演：候选策略非法时抛出可与其他问题区分的校验异常，且不静默放过")
    void invalidCandidateRejectedWithDistinctException() {
        List<Policy> bad = List.of(new Policy("bad", 2, List.of(
                new Policy.PolicyRule("dup", "**", 0, null, null),
                new Policy.PolicyRule("dup", " ", 0, Policy.Effect.ALLOW, List.of()))));
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> preview.preview(bad, List.of(target("t7", validEvidence()))));
        // 一次性报出全部问题：空 effect、空 scope、重复 ruleId
        assertNotNull(ex.issues());
        assertTrue(ex.issues().size() >= 3, "应收集全部问题，实际: " + ex.issues());
        log.info("[预演-非法候选] 被当场拒绝，问题清单={}", ex.issues());

        // 非法候选不能改变线上
        EvaluationDecision live = admission.evaluate(
                new EvaluationRequest("live-after-bad-preview", IMAGE, DIGEST, validEvidence()));
        assertEquals(EvaluationDecision.Verdict.ALLOW, live.verdict());
        assertEquals(1L, live.policyVersion());
    }

    @Test
    @DisplayName("预演：空策略列表/空目标列表都被拒绝")
    void emptyInputsRejected() {
        assertThrows(PolicyValidationException.class,
                () -> preview.preview(List.of(), List.of(target("t8", validEvidence()))));
        assertThrows(IllegalArgumentException.class,
                () -> preview.preview(denyTeamCandidate(), List.of()));
    }
}
