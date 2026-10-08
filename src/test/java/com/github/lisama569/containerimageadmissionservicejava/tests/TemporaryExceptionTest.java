package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import com.github.lisama569.containerimageadmissionservicejava.exception.TemporaryExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务域：带到期时间的临时例外。
 * 用例：有效期内 ALLOW 例外豁免证据、DENY 例外显式拒绝、判定/审计记录可见例外 ID、
 * 到期自动回落正常策略、撤销立即失效、创建即非法（到期时间已过）不残留、
 * 例外缓存到期后旧放行结论不可再用、作用域不命中不生效。
 */
@DisplayName("业务域：限时临时例外（到期/撤销后自动回到正常策略）")
class TemporaryExceptionTest {

    private static final Logger log = LoggerFactory.getLogger(TemporaryExceptionTest.class);

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String IMAGE = "reg.example.com/team/app:1.0@" + DIGEST;

    private PolicyStore policyStore;
    private AuditLog auditLog;
    private TemporaryExceptionStore exceptionStore;
    private AdmissionService admission;

    /** 可拨动的固定时钟。 */
    private MutableClock mutableClock;

    static class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant now) {
            this.now = now;
        }

        void advanceSeconds(long seconds) {
            this.now = now.plusSeconds(seconds);
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
            return now;
        }
    }

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        auditLog = new AuditLog();
        exceptionStore = new TemporaryExceptionStore();
        mutableClock = new MutableClock(NOW);
        exceptionStore.setClock(mutableClock);
        admission = new AdmissionService(policyStore, new PolicyEngine(),
                new EvidenceValidator(), auditLog, exceptionStore);
        admission.setClock(mutableClock);
    }

    @BeforeEach
    void logCase(TestInfo info) {
        log.info(">>> [业务域:限时临时例外] 执行用例: {}", info.getDisplayName());
    }

    private Evidence scan() {
        return new Evidence("scan-1", Evidence.EvidenceType.VULN_SCAN, DIGEST, 2,
                NOW.minusSeconds(3600), NOW.plusSeconds(7200),
                Map.of("scanner", "trivy", "criticalCount", "0"));
    }

    private EvaluationRequest request(String id, List<Evidence> evidence) {
        return new EvaluationRequest(id, IMAGE, DIGEST, evidence);
    }

    private TemporaryException allowException(String id, String scope, int priority,
                                              Instant expiresAt) {
        return new TemporaryException(id, scope, Policy.Effect.ALLOW, priority,
                "紧急放行", expiresAt);
    }

    private TemporaryException denyException(String id, String scope, int priority,
                                             Instant expiresAt) {
        return new TemporaryException(id, scope, Policy.Effect.DENY, priority,
                "临时封禁", expiresAt);
    }

    @Test
    @DisplayName("例外：有效期内 ALLOW 例外豁免缺失证据直接放行，且记录可见例外 ID")
    void allowExceptionBypassesMissingEvidence() {
        // 默认策略要求 SCAN+SIGNATURE；只给 SCAN，本应 MISSING_EVIDENCE
        exceptionStore.create(allowException("ex-allow", "reg.example.com/team/**", 10,
                NOW.plusSeconds(3600)));
        EvaluationDecision d = admission.evaluate(request("r-allow-ex", List.of(scan())));

        assertEquals(EvaluationDecision.Verdict.ALLOW, d.verdict());
        assertEquals("ex-allow", d.appliedExceptionId(), "判定结论必须标出用到的例外");
        log.info("[例外-放行] verdict={} appliedExceptionId={} explanation={}",
                d.verdict(), d.appliedExceptionId(), d.explanation());

        // 审计记录同样能看出用了哪个例外
        EvaluationDecision audited = auditLog.entries().get(0).decision();
        assertEquals("ex-allow", audited.appliedExceptionId());
    }

    @Test
    @DisplayName("例外：有效期内 DENY 例外显式拒绝，即使证据齐备")
    void denyExceptionBlocksEvenWithEvidence() {
        exceptionStore.create(denyException("ex-deny", "reg.example.com/team/**", 10,
                NOW.plusSeconds(3600)));
        EvaluationDecision d = admission.evaluate(request("r-deny-ex",
                List.of(scan(),
                        new Evidence("sig-1", Evidence.EvidenceType.SIGNATURE, DIGEST, 2,
                                NOW.minusSeconds(3600), NOW.plusSeconds(3600),
                                Map.of("signature", "abc", "publicKeyId", "k1")))));
        assertEquals(EvaluationDecision.Verdict.DENY, d.verdict());
        assertEquals(DenyReason.TEMPORARY_EXCEPTION_DENIED, d.denyReason());
        assertEquals("ex-deny", d.appliedExceptionId());
    }

    @Test
    @DisplayName("例外：到期后自动回到正常策略结果（缺证据重新被拒），不残留")
    void expiryReturnsToNormalPolicy() {
        exceptionStore.create(allowException("ex-exp", "reg.example.com/team/**", 10,
                NOW.plusSeconds(3600)));
        EvaluationDecision during = admission.evaluate(request("r-during", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.ALLOW, during.verdict());
        assertEquals("ex-exp", during.appliedExceptionId());

        // 时钟越过到期时刻
        mutableClock.advanceSeconds(3601);
        EvaluationDecision after = admission.evaluate(request("r-after-expiry", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, after.denyReason(),
                "到期后必须回到正常策略评估（缺证据拒绝），不得被过期例外放行");
        assertNull(after.appliedExceptionId(), "过期例外不得残留在判定记录中");
        log.info("[例外-到期] 到期后 verdict={} reason={} appliedExceptionId={}",
                after.verdict(), after.denyReason(), after.appliedExceptionId());
    }

    @Test
    @DisplayName("例外：撤销立即失效，结论回到正常策略")
    void revokeTakesEffectImmediately() {
        exceptionStore.create(allowException("ex-rev", "reg.example.com/team/**", 10,
                NOW.plusSeconds(3600)));
        assertEquals(EvaluationDecision.Verdict.ALLOW,
                admission.evaluate(request("r-before-revoke", List.of(scan()))).verdict());

        assertTrue(exceptionStore.revoke("ex-rev"));
        EvaluationDecision after = admission.evaluate(request("r-after-revoke", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, after.denyReason());
        assertNull(after.appliedExceptionId());

        // 重复撤销返回 false 且无副作用
        assertFalse(exceptionStore.revoke("ex-rev"));
        assertFalse(exceptionStore.revoke("not-exist"));
        log.info("[例外-撤销] 撤销后立即回到正常策略 reason={}", after.denyReason());
    }

    @Test
    @DisplayName("例外：撤销前缓存下的放行结论，撤销后不得再被使用")
    void cachedAllowInvalidAfterRevoke() {
        exceptionStore.create(allowException("ex-cache", "reg.example.com/team/**", 10,
                NOW.plusSeconds(3600)));
        assertEquals(EvaluationDecision.Verdict.ALLOW,
                admission.evaluate(request("r-cache-1", List.of(scan()))).verdict());

        exceptionStore.revoke("ex-cache");
        EvaluationDecision after = admission.evaluate(request("r-cache-2", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, after.verdict());
        assertNull(after.appliedExceptionId());
    }

    @Test
    @DisplayName("例外：到期后缓存的放行结论不得继续放行")
    void cachedAllowInvalidAfterExpiry() {
        exceptionStore.create(allowException("ex-exp-cache", "reg.example.com/team/**", 10,
                NOW.plusSeconds(600)));
        EvaluationDecision d1 = admission.evaluate(request("r-expc-1", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.ALLOW, d1.verdict());

        mutableClock.advanceSeconds(601);
        EvaluationDecision d2 = admission.evaluate(request("r-expc-2", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, d2.verdict());
        assertEquals(DenyReason.MISSING_EVIDENCE, d2.denyReason());
        assertNull(d2.appliedExceptionId());
    }

    @Test
    @DisplayName("例外：创建时到期时间已过（本就无效）被拒绝且不残留")
    void alreadyExpiredOnCreateRejected() {
        TemporaryException dead = allowException("ex-dead", "reg.example.com/team/**", 10,
                NOW.minusSeconds(1));
        assertThrows(IllegalArgumentException.class, () -> exceptionStore.create(dead));
        // 非法例外没有任何效果：缺证据依旧被拒
        EvaluationDecision d = admission.evaluate(request("r-dead", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, d.verdict());
        assertNull(d.appliedExceptionId());
        assertTrue(exceptionStore.entries().isEmpty());
    }

    @Test
    @DisplayName("例外：作用域不命中时不生效；多条命中时高优先级胜出")
    void scopeAndPriority() {
        // 不命中作用域的放行例外不起作用
        exceptionStore.create(allowException("ex-other", "other.example.com/**", 10,
                NOW.plusSeconds(3600)));
        EvaluationDecision d = admission.evaluate(request("r-scope-miss", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, d.verdict());
        assertNull(d.appliedExceptionId());

        // 同时命中：高优先级 DENY 压过低优先级 ALLOW
        exceptionStore.create(allowException("ex-low", "reg.example.com/team/**", 1,
                NOW.plusSeconds(3600)));
        exceptionStore.create(denyException("ex-high", "reg.example.com/team/**", 100,
                NOW.plusSeconds(3600)));
        EvaluationDecision both = admission.evaluate(request("r-priority", List.of(scan())));
        assertEquals(EvaluationDecision.Verdict.DENY, both.verdict());
        assertEquals("ex-high", both.appliedExceptionId());
    }

    @Test
    @DisplayName("例外：缺少必填字段的例外创建被拒绝")
    void malformedExceptionRejected() {
        assertThrows(IllegalArgumentException.class, () -> exceptionStore.create(
                new TemporaryException(null, "**", Policy.Effect.ALLOW, 1, null,
                        NOW.plusSeconds(3600))));
        assertThrows(IllegalArgumentException.class, () -> exceptionStore.create(
                new TemporaryException("ex-noscope", " ", Policy.Effect.ALLOW, 1, null,
                        NOW.plusSeconds(3600))));
        assertThrows(IllegalArgumentException.class, () -> exceptionStore.create(
                new TemporaryException("ex-null-effect", "**", null, 1, null,
                        NOW.plusSeconds(3600))));
    }
}
