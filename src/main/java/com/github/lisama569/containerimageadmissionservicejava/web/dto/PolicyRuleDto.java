package com.github.lisama569.containerimageadmissionservicejava.web.dto;

public record PolicyRuleDto(
        String id,
        String description,
        Integer priority,
        String effect,
        RuleConstraintsDto constraints
) {
}
