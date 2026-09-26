package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

public record RuleHit(
        String policyName,
        int policyVersion,
        String ruleId,
        int priority,
        RuleEffect effect,
        boolean satisfied,
        List<DenyFinding> findings
) {
}
