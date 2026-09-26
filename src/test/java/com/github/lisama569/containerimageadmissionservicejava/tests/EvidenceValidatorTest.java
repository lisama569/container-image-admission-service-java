package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.evidence.EvidenceValidator;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class EvidenceValidatorTest {

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
    private final EvidenceValidator validator = new EvidenceValidator();

    private Evidence signature(String id, String digest, Instant expiresAt, int formatVersion,
                               Map<String, String> attrs) {
        return new Evidence(id, Evidence.EvidenceType.SIGNATURE, digest, formatVersion,
                NOW.minusSeconds(3600), expiresAt, attrs);
    }

    @Test
    void validEvidencePasses() {
        Evidence e = signature("sig-1", DIGEST, NOW.plusSeconds(3600), 2,
                Map.of("signature", "abc", "publicKeyId", "key-1"));
        assertNull(validator.validate(e, DIGEST, NOW));
    }

    @Test
    void unboundDigestRejected() {
        Evidence e = signature("sig-1", "sha256:" + "b".repeat(64), null, 2,
                Map.of("signature", "abc", "publicKeyId", "key-1"));
        assertEquals(DenyReason.EVIDENCE_UNBOUND, validator.validate(e, DIGEST, NOW));
    }

    @Test
    void expiredEvidenceRejected() {
        Evidence e = signature("sig-1", DIGEST, NOW.minusSeconds(1), 2,
                Map.of("signature", "abc", "publicKeyId", "key-1"));
        assertEquals(DenyReason.EVIDENCE_EXPIRED, validator.validate(e, DIGEST, NOW));
    }

    @Test
    void staleFormatRejected() {
        Evidence e = signature("sig-1", DIGEST, null, 0,
                Map.of("signature", "abc", "publicKeyId", "key-1"));
        assertEquals(DenyReason.EVIDENCE_STALE_FORMAT, validator.validate(e, DIGEST, NOW));
    }

    @Test
    void incompleteManifestRejected() {
        // 缺少 publicKeyId 属性
        Evidence e = signature("sig-1", DIGEST, null, 2, Map.of("signature", "abc"));
        assertEquals(DenyReason.EVIDENCE_INCOMPLETE, validator.validate(e, DIGEST, NOW));
        // 缺少 id
        Evidence noId = new Evidence(null, Evidence.EvidenceType.SBOM, DIGEST, 2,
                NOW, null, Map.of("format", "spdx"));
        assertEquals(DenyReason.EVIDENCE_INCOMPLETE, validator.validate(noId, DIGEST, NOW));
    }
}
