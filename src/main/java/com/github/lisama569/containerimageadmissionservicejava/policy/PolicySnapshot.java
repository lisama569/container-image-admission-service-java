package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;

import java.time.Instant;
import java.util.List;

public record PolicySnapshot(long snapshotVersion, Instant createdAt, List<PolicyDefinition> policies) {
}
