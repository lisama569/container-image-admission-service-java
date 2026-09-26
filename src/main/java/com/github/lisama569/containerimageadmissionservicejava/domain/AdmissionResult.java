package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.time.Instant;
import java.util.List;

public record AdmissionResult(
        String imageReference,
        String digest,
        DecisionOutcome decision,
        DenyReasonCode reason,
        String message,
        long policySnapshotVersion,
        List<String> matchedPolicyVersions,
        List<RuleHit> ruleHits,
        List<String> evidenceIds,
        String cacheKey,
        boolean fromCache,
        Instant evaluatedAt
) {
}
