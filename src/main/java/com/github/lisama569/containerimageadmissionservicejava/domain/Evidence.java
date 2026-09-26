package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 证据：SBOM、漏洞扫描、签名或证明材料，绑定到镜像摘要。
 */
public record Evidence(
        String id,
        EvidenceType type,
        String imageDigest,
        int formatVersion,
        Instant issuedAt,
        Instant expiresAt,
        Map<String, String> attributes) {

    public enum EvidenceType {
        SBOM, VULN_SCAN, SIGNATURE, ATTESTATION
    }

    /** 当前支持的证据格式版本。 */
    public static final List<Integer> SUPPORTED_FORMAT_VERSIONS = List.of(1, 2);
}
