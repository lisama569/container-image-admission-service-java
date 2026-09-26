package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record EvidenceDto(
        String id,
        String type,
        String boundDigest,
        Instant createdAt,
        Instant expiresAt,
        Integer formatVersion,
        String signer,
        List<String> attestationTypes,
        List<String> packages,
        Map<String, Integer> vulnerabilityCounts
) {
}
