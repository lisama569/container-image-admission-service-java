package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

public record PolicyDefinition(
        String name,
        int version,
        boolean enabled,
        int priority,
        PolicyScope scope,
        List<PolicyRule> rules
) {
}
