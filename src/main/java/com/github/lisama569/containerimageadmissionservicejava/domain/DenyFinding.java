package com.github.lisama569.containerimageadmissionservicejava.domain;

public record DenyFinding(DenyReasonCode reason, String detail, String evidenceId) {
}
