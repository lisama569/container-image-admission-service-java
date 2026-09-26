package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.util.List;

public record RuleConstraintsDto(
        Boolean requireSbom,
        Boolean requireVulnScan,
        String maxSeverity,
        Boolean requireSignature,
        List<String> trustedSigners,
        List<String> requiredAttestations,
        Long maxEvidenceAgeSeconds,
        List<String> forbiddenPackages
) {
}
