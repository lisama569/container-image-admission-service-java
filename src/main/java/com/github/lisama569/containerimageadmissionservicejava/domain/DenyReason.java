package com.github.lisama569.containerimageadmissionservicejava.domain;

/**
 * 可区分的拒绝原因分类。
 */
public enum DenyReason {
    INVALID_IMAGE_REF,
    INVALID_REQUEST,
    NO_APPLICABLE_POLICY,
    POLICY_EXPLICIT_DENY,
    TAG_DRIFT,
    DIGEST_MISMATCH,
    EVIDENCE_EXPIRED,
    EVIDENCE_STALE_FORMAT,
    EVIDENCE_INCOMPLETE,
    EVIDENCE_UNBOUND,
    MISSING_EVIDENCE,
    TEMPORARY_EXCEPTION_DENIED
}
