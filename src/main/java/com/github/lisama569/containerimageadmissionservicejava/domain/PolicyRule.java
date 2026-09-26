package com.github.lisama569.containerimageadmissionservicejava.domain;

public record PolicyRule(
        String id,
        String description,
        int priority,
        RuleEffect effect,
        RuleConstraints constraints
) {
}
