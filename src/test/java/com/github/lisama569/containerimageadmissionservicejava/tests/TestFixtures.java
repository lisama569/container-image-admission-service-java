package com.github.lisama569.containerimageadmissionservicejava.tests;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvidenceType;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageManifest;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.ManifestEntry;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyScope;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect;
import com.github.lisama569.containerimageadmissionservicejava.domain.Severity;

/** 测试夹具：固定时间、固定摘要、便捷构造器。 */
final class TestFixtures {

    static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
    static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final String DIGEST = "sha256:" + "a".repeat(64);
    static final String LAYER = "sha256:" + "b".repeat(64);

    private TestFixtures() {
    }

    static ImageRef image(String digest) {
        return new ImageRef("registry.example.com", "prod/app", "v1", digest);
    }

    static ImageManifest manifest(String digest) {
        return new ImageManifest(digest, List.of(new ManifestEntry("layer.tar", LAYER, 123L)));
    }

    static Evidence sbom(String id, String digest, List<String> packages) {
        return new Evidence(id, EvidenceType.SBOM, digest, NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(30)), 1, null, null, packages, null);
    }

    static Evidence vulnScan(String id, String digest, Severity max, int count) {
        return new Evidence(id, EvidenceType.VULN_SCAN, digest, NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(30)), 1, null, null, null,
                Map.of(max == null ? Severity.NONE : max, count));
    }

    static Evidence vulnScan(String id, String digest, Map<Severity, Integer> counts) {
        return new Evidence(id, EvidenceType.VULN_SCAN, digest, NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(30)), 1, null, null, null, counts);
    }

    static Evidence signature(String id, String digest, String signer, Instant expiresAt, int format) {
        return new Evidence(id, EvidenceType.SIGNATURE, digest, NOW.minus(Duration.ofDays(1)),
                expiresAt, format, signer, null, null, null);
    }

    static Evidence attestation(String id, String digest, List<String> types, int format) {
        return new Evidence(id, EvidenceType.ATTESTATION, digest, NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(30)), format, null, types, null, null);
    }

    static RuleConstraints constraints(Boolean sbom, Boolean scan, Severity maxSeverity,
                                       Boolean sig, List<String> signers, List<String> atts) {
        return new RuleConstraints(sbom, scan, maxSeverity, sig, signers, atts,
                Duration.ofDays(30), null);
    }

    static PolicyRule allowRule(int priority, RuleConstraints c) {
        return new PolicyRule("allow-" + priority, "allow", priority, RuleEffect.ALLOW, c);
    }

    static PolicyRule denyRule(int priority, RuleConstraints c) {
        return new PolicyRule("deny-" + priority, "deny", priority, RuleEffect.DENY, c);
    }

    static PolicyDefinition policy(String name, int version, int priority,
                                   PolicyScope scope, List<PolicyRule> rules) {
        return new PolicyDefinition(name, version, true, priority, scope, rules);
    }

    static PolicyScope scopeAll() {
        return new PolicyScope("*", "*", "*");
    }
}
