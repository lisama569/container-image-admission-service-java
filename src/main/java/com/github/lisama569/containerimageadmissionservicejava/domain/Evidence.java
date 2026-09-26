package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record Evidence(
        String id,
        EvidenceType type,
        String boundDigest,
        Instant createdAt,
        Instant expiresAt,
        int formatVersion,
        String signer,
        List<String> attestationTypes,
        List<String> packages,
        Map<Severity, Integer> vulnerabilityCounts
) {
}
