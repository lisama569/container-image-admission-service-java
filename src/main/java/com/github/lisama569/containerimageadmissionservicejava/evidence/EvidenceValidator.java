package com.github.lisama569.containerimageadmissionservicejava.evidence;

import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReason;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 证据校验：摘要绑定、过期、格式版本兼容、完整性。
 *
 * <p>校验顺序固定，保证同一证据的拒绝原因确定：
 * <ol>
 *   <li>完整性（必填字段与类型相关属性缺失）→ {@link DenyReason#EVIDENCE_INCOMPLETE}</li>
 *   <li>摘要绑定（证据未绑定到目标镜像摘要）→ {@link DenyReason#EVIDENCE_UNBOUND}</li>
 *   <li>过期（expiresAt 早于当前时间）→ {@link DenyReason#EVIDENCE_EXPIRED}</li>
 *   <li>格式版本（不在支持列表中，过旧或过新）→ {@link DenyReason#EVIDENCE_STALE_FORMAT}</li>
 * </ol>
 */
@Component
public class EvidenceValidator {

    /** 各证据类型的必填属性，缺失视为清单不完整。 */
    private static final Map<Evidence.EvidenceType, List<String>> REQUIRED_ATTRIBUTES = Map.of(
            Evidence.EvidenceType.SBOM, List.of("format"),
            Evidence.EvidenceType.VULN_SCAN, List.of("scanner", "criticalCount"),
            Evidence.EvidenceType.SIGNATURE, List.of("signature", "publicKeyId"),
            Evidence.EvidenceType.ATTESTATION, List.of("predicateType"));

    /**
     * 校验单条证据，返回 null 表示有效，否则返回拒绝原因。
     */
    public DenyReason validate(Evidence evidence, String expectedDigest, Instant now) {
        Objects.requireNonNull(evidence, "evidence");
        if (evidence.id() == null || evidence.id().isBlank()
                || evidence.type() == null
                || evidence.imageDigest() == null || evidence.imageDigest().isBlank()) {
            return DenyReason.EVIDENCE_INCOMPLETE;
        }
        List<String> required = REQUIRED_ATTRIBUTES.getOrDefault(evidence.type(), List.of());
        Map<String, String> attrs = evidence.attributes() != null ? evidence.attributes() : Map.of();
        for (String key : required) {
            String value = attrs.get(key);
            if (value == null || value.isBlank()) {
                return DenyReason.EVIDENCE_INCOMPLETE;
            }
        }
        if (!evidence.imageDigest().equals(expectedDigest)) {
            return DenyReason.EVIDENCE_UNBOUND;
        }
        if (evidence.expiresAt() != null && !now.isBefore(evidence.expiresAt())) {
            return DenyReason.EVIDENCE_EXPIRED;
        }
        if (!Evidence.SUPPORTED_FORMAT_VERSIONS.contains(evidence.formatVersion())) {
            return DenyReason.EVIDENCE_STALE_FORMAT;
        }
        return null;
    }

    /**
     * 过滤出针对指定摘要的有效证据。
     */
    public List<Evidence> validEvidence(List<Evidence> evidenceList, String expectedDigest, Instant now) {
        if (evidenceList == null) {
            return List.of();
        }
        return evidenceList.stream()
                .filter(e -> validate(e, expectedDigest, now) == null)
                .toList();
    }
}
