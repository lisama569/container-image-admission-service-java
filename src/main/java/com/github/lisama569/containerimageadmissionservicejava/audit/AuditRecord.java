package com.github.lisama569.containerimageadmissionservicejava.audit;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;

import java.time.Instant;

public record AuditRecord(
        String id,
        String requestId,
        String imageReference,
        String digest,
        long policySnapshotVersion,
        AdmissionResult result,
        Instant recordedAt
) {
}
