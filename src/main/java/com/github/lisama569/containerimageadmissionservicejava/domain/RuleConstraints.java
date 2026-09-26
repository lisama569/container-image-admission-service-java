package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.time.Duration;
import java.util.List;

public record RuleConstraints(
        Boolean requireSbom,
        Boolean requireVulnScan,
        Severity maxSeverity,
        Boolean requireSignature,
        List<String> trustedSigners,
        List<String> requiredAttestations,
        Duration maxEvidenceAge,
        List<String> forbiddenPackages
) {
}
