package com.github.lisama569.containerimageadmissionservicejava.tests;

import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.attestation;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.constraints;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.denyRule;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.image;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.manifest;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.policy;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.sbom;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.scopeAll;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.signature;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.vulnScan;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.DecisionOutcome;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReasonCode;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationInput;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.ManifestEntry;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyScope;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;
import com.github.lisama569.containerimageadmissionservicejava.domain.Severity;
import com.github.lisama569.containerimageadmissionservicejava.eval.DigestNormalizer;
import com.github.lisama569.containerimageadmissionservicejava.eval.PolicyEvaluator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.ScopeMatcher;

class PolicyEvaluatorTest {

    private final PolicyEvaluator evaluator =
            new PolicyEvaluator(new ScopeMatcher(), new DigestNormalizer(), TestFixtures.FIXED_CLOCK);

    private PolicySnapshot snapshot(PolicyDefinition... policies) {
        return new PolicySnapshot(1, TestFixtures.NOW, List.of(policies));
    }

    private PolicyDefinition strictPolicy() {
        RuleConstraints c = constraints(true, true, Severity.HIGH, true,
                List.of("ci-bot"), List.of("slsa/provenance"));
        return policy("strict", 1, 100, scopeAll(),
                List.of(new PolicyRule("r1", "严格准入", 100,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.ALLOW, c)));
    }

    private List<Evidence> fullEvidence() {
        return List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo-1.0")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 2),
                signature("sig-1", TestFixtures.DIGEST, "ci-bot", TestFixtures.NOW.plusSeconds(3600), 1),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
    }

    private EvaluationInput input(List<Evidence> evidences) {
        return new EvaluationInput(image(TestFixtures.DIGEST), manifest(TestFixtures.DIGEST), evidences);
    }

    @Test
    void allowsWhenAllConstraintsSatisfied() {
        AdmissionResult r = evaluator.evaluate(input(fullEvidence()), snapshot(strictPolicy()), "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.ALLOW);
        assertThat(r.reason()).isNull();
        assertThat(r.ruleHits()).hasSize(1);
        assertThat(r.ruleHits().get(0).satisfied()).isTrue();
        assertThat(r.matchedPolicyVersions()).containsExactly("strict@v1");
    }

    @Test
    void deniesTagOnlyReferenceAsTagDrift() {
        EvaluationInput in = new EvaluationInput(
                new ImageRef("registry.example.com", "prod/app", "latest", null),
                null, List.of());
        AdmissionResult r = evaluator.evaluate(in, snapshot(strictPolicy()), "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.DENY);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.TAG_DRIFT);
    }

    @Test
    void rejectsMalformedDigest() {
        EvaluationInput in = new EvaluationInput(
                new ImageRef("registry.example.com", "prod/app", "v1", "not-a-digest"),
                null, List.of());
        AdmissionResult r = evaluator.evaluate(in, snapshot(strictPolicy()), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.INPUT_INVALID);
    }

    @Test
    void detectsManifestDigestMismatch() {
        String other = "sha256:" + "c".repeat(64);
        EvaluationInput in = new EvaluationInput(
                image(TestFixtures.DIGEST), manifest(other), fullEvidence());
        AdmissionResult r = evaluator.evaluate(in, snapshot(strictPolicy()), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.EVIDENCE_DIGEST_MISMATCH);
    }

    @Test
    void detectsIncompleteManifest() {
        EvaluationInput in = new EvaluationInput(image(TestFixtures.DIGEST),
                new com.github.lisama569.containerimageadmissionservicejava.domain.ImageManifest(
                        TestFixtures.DIGEST,
                        List.of(new ManifestEntry("x", TestFixtures.LAYER, null))),
                List.of());
        AdmissionResult r = evaluator.evaluate(in, snapshot(strictPolicy()), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.MANIFEST_INCOMPLETE);
    }

    @Test
    void detectsEvidenceBoundToDifferentDigest() {
        String other = "sha256:" + "c".repeat(64);
        EvaluationInput in = new EvaluationInput(image(TestFixtures.DIGEST),
                manifest(TestFixtures.DIGEST),
                List.of(sbom("sbom-bad", other, List.of("libfoo"))));
        AdmissionResult r = evaluator.evaluate(in, snapshot(strictPolicy()), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.EVIDENCE_DIGEST_MISMATCH);
    }

    @Test
    void noPolicyEnabledGivesPolicyNotFound() {
        PolicySnapshot empty = new PolicySnapshot(1, TestFixtures.NOW, List.of());
        AdmissionResult r = evaluator.evaluate(input(fullEvidence()), empty, "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.POLICY_NOT_FOUND);
    }

    @Test
    void noScopeMatchGivesNoRuleMatched() {
        PolicyDefinition p = policy("narrow", 1, 100,
                new PolicyScope("other.registry.io", "*", "*"),
                List.of(new PolicyRule("r", "", 100,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.ALLOW,
                        new RuleConstraints(null, null, null, null, null, null, null, null))));
        AdmissionResult r = evaluator.evaluate(input(fullEvidence()), snapshot(p), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.NO_RULE_MATCHED);
    }

    @Test
    void missingEvidenceKindsAreDistinguishable() {
        // 只有 sbom，缺扫描/签名/证明
        AdmissionResult r = evaluator.evaluate(
                input(List.of(sbom("s", TestFixtures.DIGEST, List.of("x")))),
                snapshot(strictPolicy()), "k", false);
        assertThat(r.decision()).isEqualTo(DecisionOutcome.DENY);
        List<DenyReasonCode> codes = r.ruleHits().get(0).findings().stream()
                .map(com.github.lisama569.containerimageadmissionservicejava.domain.DenyFinding::reason).toList();
        assertThat(codes).contains(
                DenyReasonCode.VULN_SCAN_MISSING,
                DenyReasonCode.SIGNATURE_MISSING,
                DenyReasonCode.ATTESTATION_MISSING);
    }

    @Test
    void expiredSignatureIsDistinguishable() {
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 1),
                signature("sig-1", TestFixtures.DIGEST, "ci-bot",
                        TestFixtures.NOW.minusSeconds(1), 1),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
        AdmissionResult r = evaluator.evaluate(input(ev), snapshot(strictPolicy()), "k", false);
        assertThat(r.ruleHits().get(0).findings()).isNotEmpty();
        assertThat(r.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.SIGNATURE_EXPIRED);
    }

    @Test
    void staleFormatEvidenceIsDetected() {
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 1),
                signature("sig-1", TestFixtures.DIGEST, "ci-bot",
                        TestFixtures.NOW.plusSeconds(3600), 0),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
        AdmissionResult r = evaluator.evaluate(input(ev), snapshot(strictPolicy()), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.EVIDENCE_STALE);
    }

    @Test
    void untrustedSignerIsDetected() {
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 1),
                signature("sig-1", TestFixtures.DIGEST, "mallory",
                        TestFixtures.NOW.plusSeconds(3600), 1),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
        AdmissionResult r = evaluator.evaluate(input(ev), snapshot(strictPolicy()), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.SIGNATURE_UNTRUSTED_SIGNER);
    }

    @Test
    void vulnerabilityThresholdExceeded() {
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.CRITICAL, 1),
                signature("sig-1", TestFixtures.DIGEST, "ci-bot",
                        TestFixtures.NOW.plusSeconds(3600), 1),
                attestation("att-1", TestFixtures.DIGEST, List.of("slsa/provenance"), 1));
        AdmissionResult r = evaluator.evaluate(input(ev), snapshot(strictPolicy()), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.VULN_THRESHOLD_EXCEEDED);
    }

    @Test
    void higherPriorityDenyRuleVetoes() {
        RuleConstraints denyCritical = constraints(null, true, Severity.CRITICAL, null, null, null);
        PolicyDefinition p = policy("mix", 1, 100, scopeAll(), List.of(
                denyRule(10, denyCritical),
                new PolicyRule("allow", "", 100,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.ALLOW,
                        constraints(true, true, null, null, null, null))));
        // 扫描含 CRITICAL，高优先级 DENY 成立，直接否决；低优先级 ALLOW 不再参与
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.CRITICAL, 1));
        AdmissionResult r = evaluator.evaluate(input(ev), snapshot(p), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.RULE_VIOLATION);
        assertThat(r.ruleHits()).hasSize(1);
        assertThat(r.ruleHits().get(0).ruleId()).isEqualTo("deny-10");
    }

    @Test
    void samePriorityAllowAndDenyBothSatisfiedIsConflict() {
        PolicyDefinition p = policy("conflict", 1, 100, scopeAll(), List.of(
                new PolicyRule("a-allow", "", 50,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.ALLOW,
                        constraints(true, null, null, null, null, null)),
                new PolicyRule("a-deny", "", 50,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.DENY,
                        constraints(null, true, null, null, null, null))));
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 0));
        AdmissionResult r = evaluator.evaluate(input(ev), snapshot(p), "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.POLICY_CONFLICT);
    }

    @Test
    void samePriorityAcrossPoliciesConflictIsDetected() {
        PolicyDefinition p1 = policy("pol-a", 1, 100, scopeAll(), List.of(
                new PolicyRule("ra", "", 50,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.ALLOW,
                        constraints(true, null, null, null, null, null))));
        PolicyDefinition p2 = policy("pol-b", 1, 100, scopeAll(), List.of(
                new PolicyRule("rb", "", 50,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.DENY,
                        constraints(null, true, null, null, null, null))));
        List<Evidence> ev = List.of(
                sbom("sbom-1", TestFixtures.DIGEST, List.of("libfoo")),
                vulnScan("scan-1", TestFixtures.DIGEST, Severity.LOW, 0));
        PolicySnapshot snap = new PolicySnapshot(1, TestFixtures.NOW, List.of(p1, p2));
        AdmissionResult r = evaluator.evaluate(input(ev), snap, "k", false);
        assertThat(r.reason()).isEqualTo(DenyReasonCode.POLICY_CONFLICT);
    }

    @Test
    void expiredEvidenceByMaxAgeIsDetected() {
        RuleConstraints c = new RuleConstraints(true, null, null, null, null, null,
                Duration.ofHours(1), null);
        PolicyDefinition p = policy("age", 1, 100, scopeAll(), List.of(
                new PolicyRule("r", "", 100,
                        com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect.ALLOW, c)));
        Evidence old = new Evidence("old-sbom",
                com.github.lisama569.containerimageadmissionservicejava.domain.EvidenceType.SBOM,
                TestFixtures.DIGEST, TestFixtures.NOW.minus(Duration.ofDays(2)),
                TestFixtures.NOW.plus(Duration.ofDays(30)), 1, null, null, List.of("x"), null);
        AdmissionResult r = evaluator.evaluate(input(List.of(old)), snapshot(p), "k", false);
        assertThat(r.ruleHits().get(0).findings().get(0).reason())
                .isEqualTo(DenyReasonCode.EVIDENCE_EXPIRED);
    }

    @Test
    void repeatedEvaluationIsDeterministic() {
        PolicySnapshot snap = snapshot(strictPolicy());
        AdmissionResult r1 = evaluator.evaluate(input(fullEvidence()), snap, "k", false);
        AdmissionResult r2 = evaluator.evaluate(input(fullEvidence()), snap, "k", false);
        assertThat(r1.decision()).isEqualTo(r2.decision());
        assertThat(r1.reason()).isEqualTo(r2.reason());
    }
}
