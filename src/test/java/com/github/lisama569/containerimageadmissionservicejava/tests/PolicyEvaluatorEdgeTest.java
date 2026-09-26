package com.github.lisama569.containerimageadmissionservicejava.tests;

import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.attestation;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.image;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.manifest;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.policy;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.scopeAll;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.signature;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.vulnScan;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.DecisionOutcome;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReasonCode;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationInput;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvidenceType;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect;
import com.github.lisama569.containerimageadmissionservicejava.domain.Severity;
import com.github.lisama569.containerimageadmissionservicejava.eval.DigestNormalizer;
import com.github.lisama569.containerimageadmissionservicejava.eval.PolicyEvaluator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.ScopeMatcher;

class PolicyEvaluatorEdgeTest {

    private final PolicyEvaluator evaluator =
            new PolicyEvaluator(new ScopeMatcher(), new DigestNormalizer(), TestFixtures.FIXED_CLOCK);

    private PolicySnapshot snapshot(PolicyDefinition p) {
        return new PolicySnapshot(1, TestFixtures.NOW, List.of(p));
    }

    @Test
    void oldFormatSbomIsStale() {
        RuleConstraints c = new RuleConstraints(true, null, null, null, null, null, null, null);
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("r", "", 100, RuleEffect.ALLOW, c)));
        Evidence old = new Evidence("old", EvidenceType.SBOM, TestFixtures.DIGEST,
                TestFixtures.NOW.minus(Duration.ofDays(1)), TestFixtures.NOW.plus(Duration.ofDays(30)),
                0, null, null, List.of("x"), null);
        AdmissionResult r = evaluator.evaluate(
                new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST), List.of(old)),
                snapshot(p), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason()).isEqualTo(DenyReasonCode.EVIDENCE_STALE);
    }

    @Test
    void oldFormatAttestationIsStale() {
        RuleConstraints c = new RuleConstraints(null, null, null, null, null,
                List.of("slsa/provenance"), null, null);
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("r", "", 100, RuleEffect.ALLOW, c)));
        AdmissionResult r = evaluator.evaluate(
                new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST),
                        List.of(attestation("att", TestFixtures.DIGEST, List.of("slsa/provenance"), 0))),
                snapshot(p), "k", false);
        // 唯一证明是旧格式 → 不视为可用；必需类型未被有效证据覆盖，拒绝且原因可区分
        assertThat(r.decision()).isEqualTo(DecisionOutcome.DENY);
        List<DenyReasonCode> codes = r.ruleHits().get(0).findings().stream()
                .map(com.github.lisama569.containerimageadmissionservicejava.domain.DenyFinding::reason)
                .toList();
        assertThat(codes).contains(DenyReasonCode.EVIDENCE_STALE, DenyReasonCode.ATTESTATION_TYPE_MISSING);
    }

    @Test
    void forbiddenPackageTriggersRuleViolation() {
        RuleConstraints c = new RuleConstraints(null, null, null, null, null, null, null,
                List.of("evil-lib"));
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("r", "", 100, RuleEffect.ALLOW, c)));
        Evidence sbom = new Evidence("sbom", EvidenceType.SBOM, TestFixtures.DIGEST,
                TestFixtures.NOW.minus(Duration.ofDays(1)), TestFixtures.NOW.plus(Duration.ofDays(30)),
                1, null, null, List.of("evil-lib"), null);
        AdmissionResult r = evaluator.evaluate(
                new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST), List.of(sbom)),
                snapshot(p), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason()).isEqualTo(DenyReasonCode.RULE_VIOLATION);
    }

    @Test
    void bareHexDigestRequestAcceptedAndNormalized() {
        // 旧式客户端直接提交 64 位十六进制摘要，应兼容补全为 sha256:
        RuleConstraints c = new RuleConstraints(null, true, null, null, null, null, null, null);
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("r", "", 100, RuleEffect.ALLOW, c)));
        String hex = "a".repeat(64);
        EvaluationInput in = new EvaluationInput(
                new ImageRef("registry.example.com", "prod/app", "v1", hex),
                new com.github.lisama569.containerimageadmissionservicejava.domain.ImageManifest(
                        TestFixtures.DIGEST,
                        List.of(new com.github.lisama569.containerimageadmissionservicejava.domain.ManifestEntry(
                                "l", TestFixtures.LAYER, 1L))),
                List.of(vulnScan("scan", TestFixtures.DIGEST, Severity.NONE, 0)));
        AdmissionResult r = evaluator.evaluate(in, snapshot(p), "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(r.digest()).isEqualTo(TestFixtures.DIGEST);
    }

    @Test
    void attestationTypeCoverageRequired() {
        RuleConstraints c = new RuleConstraints(null, null, null, null, null,
                List.of("slsa/provenance", "vuln/vex"), null, null);
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("r", "", 100, RuleEffect.ALLOW, c)));
        AdmissionResult r = evaluator.evaluate(
                new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST),
                        List.of(attestation("att", TestFixtures.DIGEST, List.of("slsa/provenance"), 1))),
                snapshot(p), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.ATTESTATION_TYPE_MISSING);
    }

    @Test
    void denyRuleWhenConstraintNotMetDoesNotVeto() {
        // DENY 规则：“存在 CRITICAL 漏洞”时才否决；扫描仅 LOW 时不触发 → 不否决（放行）
        RuleConstraints denyCritical = new RuleConstraints(null, true, Severity.CRITICAL,
                null, null, null, null, null);
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("d", "", 100, RuleEffect.DENY, denyCritical)));
        EvaluationInput in = new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST),
                List.of(vulnScan("scan", TestFixtures.DIGEST, Severity.LOW, 1)));
        AdmissionResult r = evaluator.evaluate(in, snapshot(p), "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(r.ruleHits().get(0).effect()).isEqualTo(RuleEffect.DENY);
        assertThat(r.ruleHits().get(0).satisfied()).isFalse();
    }

    @Test
    void denyRuleFiresWhenCriticalPresent() {
        RuleConstraints denyCritical = new RuleConstraints(null, true, Severity.CRITICAL,
                null, null, null, null, null);
        PolicyDefinition p = policy("p", 1, 100, scopeAll(),
                List.of(new PolicyRule("d", "", 100, RuleEffect.DENY, denyCritical)));
        EvaluationInput in = new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST),
                List.of(vulnScan("scan", TestFixtures.DIGEST, Severity.CRITICAL, 1)));
        AdmissionResult r = evaluator.evaluate(in, snapshot(p), "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.DENY);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.RULE_VIOLATION);
    }

    @Test
    void multipleCrossPolicyDeniesAreNotConflict() {
        // 两条来自不同策略、同优先级的 DENY 同时触发：结论一致，按 RULE_VIOLATION 拒绝，不报冲突
        RuleConstraints denyCritical = new RuleConstraints(null, true, Severity.CRITICAL,
                null, null, null, null, null);
        PolicyDefinition p1 = policy("pol-a", 1, 100, scopeAll(),
                List.of(new PolicyRule("da", "", 50, RuleEffect.DENY, denyCritical)));
        PolicyDefinition p2 = policy("pol-b", 1, 200, scopeAll(),
                List.of(new PolicyRule("db", "", 50, RuleEffect.DENY, denyCritical)));
        PolicySnapshot snap = new PolicySnapshot(1, TestFixtures.NOW, List.of(p1, p2));
        EvaluationInput in = new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST),
                List.of(vulnScan("scan", TestFixtures.DIGEST, Severity.CRITICAL, 1)));
        AdmissionResult r = evaluator.evaluate(in, snap, "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.DENY);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.RULE_VIOLATION);
        assertThat(r.ruleHits()).hasSize(2);
    }
}
