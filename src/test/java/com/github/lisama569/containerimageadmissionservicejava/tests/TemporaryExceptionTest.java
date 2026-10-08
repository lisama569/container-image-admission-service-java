package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.ExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 带到期时间的临时例外业务场景测试：生效、判定可见、到期、撤销、非法与不残留。
 */
class TemporaryExceptionTest {

    private static final String DIGEST = "sha256:" + "d".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:3.0@" + DIGEST;
    private static final String OTHER_IMAGE = "reg.example.com/other/web:1.0@" + DIGEST;

    private PolicyStore policyStore;
    private AuditLog auditLog;
    private ExceptionStore exceptionStore;
    private AdmissionService service;
    private final MutableClock clock = new MutableClock(NOW);
    private final ScenarioLogger scenario = ScenarioLogger.of(getClass());

    static class MutableClock extends Clock {
        private final AtomicLong millis;

        MutableClock(Instant start) {
            this.millis = new AtomicLong(start.toEpochMilli());
        }

        void setInstant(Instant instant) {
            millis.set(instant.toEpochMilli());
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis.get());
        }
    }

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        PolicyEngine engine = new PolicyEngine();
        auditLog = new AuditLog();
        exceptionStore = new ExceptionStore(engine);
        service = new AdmissionService(policyStore, engine, new EvidenceValidator(),
                auditLog, exceptionStore);
        service.setClock(clock);
        exceptionStore.setClock(clock);
    }

    /** 只给签名、不给漏洞扫描：默认策略下应因缺证据被拒，用来验证例外的放行覆盖。 */
    private EvaluationRequest insufficientRequest(String id) {
        Evidence onlySig = new Evidence("sig-1", Evidence.EvidenceType.SIGNATURE, DIGEST, 2,
                NOW.minusSeconds(3600), NOW.plusSeconds(3600),
                Map.of("signature", "abc", "publicKeyId", "key-1"));
        return new EvaluationRequest(id, IMAGE, DIGEST, List.of(onlySig));
    }

    private TemporaryException exception(String id, String scope, Instant expiresAt) {
        return new TemporaryException(id, scope, Policy.Effect.ALLOW, expiresAt, NOW,
                "紧急修复窗口放行");
    }

    @Test
    void activeExceptionOverridesNormalPolicyAndIsVisibleInDecisionAndAudit() {
        scenario.scenario("例外生效-覆盖正常策略，结论与审计可识别");
        EvaluationDecision denied = service.evaluate(insufficientRequest("ex-base"));
        scenario.casee("无例外时", "DENY/MISSING_EVIDENCE");
        assertEquals(EvaluationDecision.Verdict.DENY, denied.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, denied.denyReason());
        assertNull(denied.appliedExceptionId());

        exceptionStore.add(exception("ex-1", "reg.example.com/team/**", NOW.plusSeconds(3600)));
        EvaluationDecision allowed = service.evaluate(insufficientRequest("ex-allow"));
        scenario.casee("有效期内、作用域命中", "ALLOW 且 appliedExceptionId=ex-1");
        assertEquals(EvaluationDecision.Verdict.ALLOW, allowed.verdict());
        assertEquals("ex-1", allowed.appliedExceptionId());
        assertTrue(allowed.explanation().contains("临时例外 ex-1"));

        scenario.casee("审计记录", "同一结论带 appliedExceptionId=ex-1");
        EvaluationDecision audited = auditLog.entries().stream()
                .filter(e -> e.requestId().equals("ex-allow")).findFirst().orElseThrow().decision();
        assertEquals("ex-1", audited.appliedExceptionId());
        scenario.summary("例外在有效期内按例外处理，判定记录与审计都能看出用了哪条例外");
    }

    @Test
    void exceptionScopeDoesNotLeakToOtherImages() {
        scenario.scenario("例外作用域-不越界");
        exceptionStore.add(exception("ex-scope", "reg.example.com/team/**", NOW.plusSeconds(3600)));
        EvaluationRequest other = new EvaluationRequest("ex-other", OTHER_IMAGE, DIGEST,
                insufficientRequest("x").evidenceList());
        EvaluationDecision d = service.evaluate(other);
        scenario.casee("其他仓库镜像", "仍按正常策略 DENY，不套用 team 下例外");
        assertEquals(EvaluationDecision.Verdict.DENY, d.verdict());
        assertNull(d.appliedExceptionId());
        scenario.summary("例外只对声明的范围生效，不扩大放行面");
    }

    @Test
    void expiredExceptionFallsBackToNormalPolicyAndDoesNotBypassDeny() {
        scenario.scenario("例外到期-自动回到正常策略，不残留放行");
        exceptionStore.add(exception("ex-exp", "reg.example.com/team/**", NOW.plusSeconds(600)));
        EvaluationDecision before = service.evaluate(insufficientRequest("exp-1"));
        scenario.casee("到期前", "ALLOW + appliedExceptionId=ex-exp");
        assertEquals(EvaluationDecision.Verdict.ALLOW, before.verdict());

        // 时钟越过到期时间；同一请求（同 requestId 幂等键仅影响审计）必须回到正常结论
        clock.setInstant(NOW.plusSeconds(601));
        EvaluationDecision after = service.evaluate(insufficientRequest("exp-2"));
        scenario.casee("到期后再评估", "DENY/MISSING_EVIDENCE，appliedExceptionId=null");
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, after.denyReason());
        assertNull(after.appliedExceptionId());

        // 即使线上策略是显式 DENY，过期例外也不能把该拒的放过去
        policyStore.update(List.of(new Policy("deny-all", 1, List.of(
                new Policy.PolicyRule("deny-all", "**", 100, Policy.Effect.DENY, List.of())))));
        EvaluationDecision denied = service.evaluate(insufficientRequest("exp-3"));
        scenario.casee("显式 DENY + 已过期例外", "仍 DENY/POLICY_EXPLICIT_DENY");
        assertEquals(EvaluationDecision.Verdict.DENY, denied.verdict());
        assertEquals(DenyReason.POLICY_EXPLICIT_DENY, denied.denyReason());
        scenario.summary("例外到期即失效，结论自动回落，绝不会因过期例外放行该拒镜像");
    }

    @Test
    void revokedExceptionImmediatelyStopsApplying() {
        scenario.scenario("例外撤销-立即失效");
        exceptionStore.add(exception("ex-rev", "reg.example.com/team/**", NOW.plusSeconds(3600)));
        assertEquals(EvaluationDecision.Verdict.ALLOW,
                service.evaluate(insufficientRequest("rev-1")).verdict());
        scenario.casee("撤销前", "ALLOW");

        assertTrue(exceptionStore.revoke("ex-rev"));
        EvaluationDecision after = service.evaluate(insufficientRequest("rev-2"));
        scenario.casee("撤销后再评估", "立即回到 DENY/MISSING_EVIDENCE");
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, after.denyReason());
        assertNull(after.appliedExceptionId());
        assertFalse(exceptionStore.revoke("ex-rev"), "重复撤销返回 false");
        scenario.summary("撤销物理移除例外，后续评估不可能再命中");
    }

    @Test
    void cachedExceptionAllowExpiresAndFallsBack() {
        scenario.scenario("例外缓存-到期后旧的放行缓存不得继续命中");
        exceptionStore.add(exception("ex-cache", "reg.example.com/team/**", NOW.plusSeconds(600)));
        // 同一 requestId 重复评估：第二次会命中缓存
        EvaluationDecision first = service.evaluate(insufficientRequest("cache-1"));
        EvaluationDecision cached = service.evaluate(insufficientRequest("cache-1"));
        scenario.casee("例外有效期内重复评估", "均 ALLOW 且带 appliedExceptionId=ex-cache");
        assertEquals(EvaluationDecision.Verdict.ALLOW, first.verdict());
        assertEquals(EvaluationDecision.Verdict.ALLOW, cached.verdict());
        assertEquals("ex-cache", cached.appliedExceptionId());

        clock.setInstant(NOW.plusSeconds(601));
        EvaluationDecision afterExpiry = service.evaluate(insufficientRequest("cache-1"));
        scenario.casee("越过例外到期时间后，同一缓存键再评估", "旧 ALLOW 缓存失效，回到 DENY/MISSING_EVIDENCE");
        assertEquals(EvaluationDecision.Verdict.DENY, afterExpiry.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, afterExpiry.denyReason());
        assertNull(afterExpiry.appliedExceptionId());
        scenario.summary("例外放行缓存的有效期不晚于例外到期时间，到期自动失效，不残留");
    }

    @Test
    void invalidExceptionsAreRejected() {
        scenario.scenario("例外非法-当场拒绝，不留隐患");
        assertThrows(IllegalArgumentException.class,
                () -> exceptionStore.add(exception("ex-noscope", " ", NOW.plusSeconds(10))));
        scenario.casee("空作用域", "拒绝");
        assertThrows(IllegalArgumentException.class,
                () -> exceptionStore.add(exception("ex-past", "**", NOW.minusSeconds(1))));
        scenario.casee("创建时已过期", "拒绝（防止写入即无效的例外）");
        assertThrows(IllegalArgumentException.class,
                () -> exceptionStore.add(new TemporaryException("ex-null-eff", "**", null,
                        NOW.plusSeconds(10), NOW, null)));
        scenario.casee("缺少到期时间", "拒绝（限时例外必须带 expiresAt）");
        exceptionStore.add(exception("ex-dup", "**", NOW.plusSeconds(10)));
        assertThrows(IllegalArgumentException.class,
                () -> exceptionStore.add(exception("ex-dup", "**", NOW.plusSeconds(20))));
        scenario.casee("id 重复", "拒绝");
        scenario.summary("无效例外无法写入，自然不会污染判定");
    }
}
