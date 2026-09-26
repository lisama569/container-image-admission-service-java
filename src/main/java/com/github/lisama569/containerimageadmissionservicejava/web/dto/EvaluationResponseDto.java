package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record EvaluationResponseDto(
        String requestId,
        String imageReference,
        String digest,
        String decision,
        String reason,
        String message,
        long policySnapshotVersion,
        List<Map<String, Object>> ruleHits,
        List<String> evidenceIds,
        String cacheKey,
        boolean fromCache,
        Instant evaluatedAt
) {
}
