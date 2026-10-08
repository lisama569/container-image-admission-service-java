package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.RehearsalReport;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.ExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.exception.InvalidCandidatePolicyException;
import com.github.lisama569.containerimageadmissionservicejava.policy.CandidatePolicyValidator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import com.github.lisama569.containerimageadmissionservicejava.service.RehearsalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 预演（dry-run）业务场景测试。
 */
class RehearsalServiceTest {

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:1.0@" + DIGEST;

    private PolicyStore policyStore;
    private AuditLog auditLog;
    private ExceptionStore exceptionStore;
    private AdmissionService admissionService;
    private RehearsalService rehearsalService;
    private final ScenarioLogger scenario = ScenarioLogger.of(getClass());

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        PolicyEngine engine = new PolicyEngine();
        auditLog = new AuditLog();
        exceptionStore = new ExceptionStore(engine);
        admissionService = new AdmissionService(policyStore, engine, new EvidenceValidator(),
                auditLog, exceptionStore);
        Clock fixed = Clock.fixed(NOW, ZoneOffset.UTC);
        admissionService.setClock(fixed);
        exceptionStore.setClock(fixed);
        rehearsalService = new RehearsalService(admissionService, policyStore,
                new CandidatePolicyValidator());
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

    private Policy allowNoEvidenceRule() {
        // 候选策略：命中即 ALLOW、不要求证据
        return new Policy("candidate", 1, List.of(
                new Policy.PolicyRule("cand-allow-all", "**", 0, Policy.Effect.ALLOW, List.of())));
    }

    private Policy denyAllRule() {
        return new Policy("candidate", 1, List.of(
                new Policy.PolicyRule("cand-deny-all", "**", 0, Policy.Effect.DENY, List.of())));
    }

    @Test
    void detectsConclusionChangedFromAllowToDeny() {
        scenario.scenario("预演-结论变化检测（ALLOW -> DENY）");
        scenario.casee("基线放行 + 候选显式拒绝", "changes 中给出 before=ALLOW/after=DENY/POLICY_EXPLICIT_DENY");
        RehearsalReport report = rehearsalService.rehearse(
                List.of(denyAllRule()), List.of(request("reh-1")));

        assertEquals(1, report.changes().size());
        RehearsalReport.ImageChange change = report.changes().get(0);
        assertEquals(IMAGE, change.imageRef());
        assertEquals(EvaluationDecision.Verdict.ALLOW, change.before().verdict());
        assertEquals(EvaluationDecision.Verdict.DENY, change.after().verdict());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, change.after().denyReason());
        assertTrue(report.unchanged().isEmpty());
        scenario.summary("正确识别 1 个由 ALLOW 变 DENY 的镜像，并给出前后结论");
    }

    @Test
    void detectsDenyToAllowAndSeparatesUnchangedImages() {
        scenario.scenario("预演-混合批次（DENY -> ALLOW 与不变镜像同时出现）");
        // 线上先切成“显式拒绝”，基线为 DENY；候选放开
        policyStore.update(List.of(denyAllRule()));
        scenario.casee("基线 DENY、候选 ALLOW", "进入 changes（before=DENY/after=ALLOW）");
        scenario.casee("同一批再放一个相同请求", "同样进入 changes，unchanged 为空（此策略下无不变项）");
        RehearsalReport report = rehearsalService.rehearse(
                List.of(allowNoEvidenceRule()),
                List.of(request("reh-a"), request("reh-b")));

        assertEquals(2, report.changes().size());
        for (RehearsalReport.ImageChange change : report.changes()) {
            assertEquals(EvaluationDecision.Verdict.DENY, change.before().verdict());
            assertEquals(EvaluationDecision.Verdict.ALLOW, change.after().verdict());
        }

        // 候选与当前一致的镜像应进入 unchanged
        Policy sameAsCurrent = denyAllRule();
        RehearsalReport sameReport = rehearsalService.rehearse(
                List.of(sameAsCurrent), List.of(request("reh-c")));
        scenario.casee("候选与线上一致", "镜像进入 unchanged，changes 为空");
        assertTrue(sameReport.changes().isEmpty());
        assertEquals(1, sameReport.unchanged().size());
        scenario.summary("变化镜像与不变镜像被正确分流");
    }

    @Test
    void rehearsalDoesNotAffectLiveDecisionOrAudit() {
        scenario.scenario("预演-无副作用（不影响线上判定、不留审计记录）");
        EvaluationDecision liveBefore = admissionService.evaluate(request("live-1"));
        scenario.casee("先记录线上结论", "ALLOW（v1 默认策略）");

        RehearsalReport report = rehearsalService.rehearse(
                List.of(denyAllRule()), List.of(request("reh-x")));
        scenario.casee("用“全拒绝”候选预演", "报告里 after=DENY");
        assertEquals(EvaluationDecision.Verdict.DENY, report.changes().get(0).after().verdict());

        EvaluationDecision liveAfter = admissionService.evaluate(request("live-2"));
        scenario.casee("预演后再次线上评估", "仍然 ALLOW 且版本仍为 1，未被候选污染");
        assertEquals(EvaluationDecision.Verdict.ALLOW, liveAfter.verdict());
        assertEquals(1L, liveAfter.policyVersion());
        // 只有 live-1、live-2 两条正式审计；预演请求 reh-x 不得留下记录
        scenario.casee("检查审计", "只有正式评估的 2 条，无预演请求 reh-x");
        assertEquals(2, auditLog.size());
        assertTrue(auditLog.entries().stream().noneMatch(e -> e.requestId().equals("reh-x")));
        // 线上策略快照未被替换
        assertEquals(1L, policyStore.snapshot().version());
        scenario.summary("预演只读不写，线上判定与审计均未受影响");
    }

    @Test
    void invalidCandidateIsRejectedWithDistinctFeedback() {
        scenario.scenario("预演-候选策略非法（错误可与其他问题区分）");
        Policy duplicateRuleId = new Policy("p", 1, List.of(
                new Policy.PolicyRule("dup", "**", 0, Policy.Effect.ALLOW, List.of()),
                new Policy.PolicyRule("dup", "reg.example.com/**", 0, Policy.Effect.DENY, List.of())));
        InvalidCandidatePolicyException ex = assertThrows(InvalidCandidatePolicyException.class,
                () -> rehearsalService.rehearse(List.of(duplicateRuleId), List.of(request("reh-bad"))));
        scenario.casee("ruleId 重复", "抛 InvalidCandidatePolicyException 且 errors 含重复说明");
        assertTrue(ex.errors().stream().anyMatch(s -> s.contains("ruleId") && s.contains("重复")),
                "应报告 ruleId 重复，实际: " + ex.errors());

        Policy emptyRules = new Policy("p", 1, List.of());
        InvalidCandidatePolicyException ex2 = assertThrows(InvalidCandidatePolicyException.class,
                () -> rehearsalService.rehearse(List.of(emptyRules), List.of(request("reh-bad2"))));
        scenario.casee("策略无任何规则", "被拒绝并提示“不包含任何规则”，不悄悄放过");
        assertTrue(playHasNoRulesError(ex2));

        assertThrows(InvalidCandidatePolicyException.class,
                () -> rehearsalService.rehearse(List.of(), List.of(request("reh-empty"))));
        scenario.casee("空策略列表", "同样被明确拒绝");
        // 非法候选不得污染线上：版本仍是 1
        assertFalse(policyStore.snapshot().policies().isEmpty());
        assertEquals(1L, policyStore.snapshot().version());
        scenario.summary("候选填写错误被当场、分类地拒绝，且没有任何副作用");
    }

    private boolean playHasNoRulesError(InvalidCandidatePolicyException ex) {
        return ex.errors().stream().anyMatch(s -> s.contains("不包含任何规则"));
    }
}
