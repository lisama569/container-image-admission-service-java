package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.util.List;

public record PolicyDefinitionDto(
        String name,
        Integer version,
        Boolean enabled,
        Integer priority,
        PolicyScopeDto scope,
        List<PolicyRuleDto> rules
) {
}
