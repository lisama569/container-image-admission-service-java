package com.github.lisama569.containerimageadmissionservicejava.service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.common.ApiException;
import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyFinding;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationInput;
import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvidenceType;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageManifest;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.ManifestEntry;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyScope;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleHit;
import com.github.lisama569.containerimageadmissionservicejava.domain.Severity;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.EvaluationRequestDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.EvaluationResponseDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.ManifestDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.ManifestEntryDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.PolicyDefinitionDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.PolicyRuleDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.PolicyScopeDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.RuleConstraintsDto;

/**
 * DTO 与领域模型互转。所有非法枚举/缺失必填项都抛 {@link ApiException}(INPUT_INVALID)，
 * 不做静默默认，防止脏输入被放行。
 */
@Component
public class DtoMapper {

    public EvaluationInput toInput(EvaluationRequestDto dto) {
        if (dto == null) {
            throw new ApiException("INPUT_INVALID: 请求体为空");
        }
        ImageRef image = parseImageRef(dto.image(), dto.tag(), dto.digest());
        ImageManifest manifest = parseManifest(dto.manifest());
        List<Evidence> evidences = new ArrayList<>();
        if (dto.evidences() != null) {
            for (var e : dto.evidences()) {
                evidences.add(parseEvidence(e));
            }
        }
        return new EvaluationInput(image, manifest, List.copyOf(evidences));
    }

    private ImageRef parseImageRef(String image, String tag, String digest) {
        if (image == null || image.isBlank()) {
            throw new ApiException("INPUT_INVALID: image 不能为空");
        }
        String registry = "";
        String repository;
        String rest = image.trim();
        // 第一个带点号或冒号端口的段视为 registry
        int firstSlash = rest.indexOf('/');
        if (firstSlash > 0) {
            String head = rest.substring(0, firstSlash);
            if (head.contains(".") || head.contains(":")) {
                registry = head;
                rest = rest.substring(firstSlash + 1);
            }
        }
        int at = rest.indexOf('@');
        String digestFromRef = null;
        if (at >= 0) {
            digestFromRef = rest.substring(at + 1);
            rest = rest.substring(0, at);
        }
        int colon = rest.indexOf(':');
        String tagFromRef = null;
        if (colon >= 0) {
            tagFromRef = rest.substring(colon + 1);
            rest = rest.substring(0, colon);
        }
        repository = rest;
        if (repository.isBlank()) {
            throw new ApiException("INPUT_INVALID: 无法解析镜像 repository: " + image);
        }
        String effectiveTag = tag != null ? tag : tagFromRef;
        String effectiveDigest = digest != null ? digest : digestFromRef;
        if (effectiveTag == null && effectiveDigest == null) {
            throw new ApiException("INPUT_INVALID: 镜像必须提供 tag 或 digest: " + image);
        }
        return new ImageRef(registry, repository, effectiveTag, effectiveDigest);
    }

    private ImageManifest parseManifest(ManifestDto dto) {
        if (dto == null) {
            return null;
        }
        if (dto.digest() == null || dto.digest().isBlank()) {
            throw new ApiException("INPUT_INVALID: manifest.digest 不能为空");
        }
        List<ManifestEntry> entries = new ArrayList<>();
        if (dto.entries() != null) {
            for (ManifestEntryDto e : dto.entries()) {
                entries.add(new ManifestEntry(e.name(), e.digest(), e.size()));
            }
        }
        return new ImageManifest(dto.digest(), List.copyOf(entries));
    }

    private Evidence parseEvidence(com.github.lisama569.containerimageadmissionservicejava.web.dto.EvidenceDto e) {
        EvidenceType type;
        try {
            type = EvidenceType.valueOf(e.type() == null ? "" : e.type().trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new ApiException("INPUT_INVALID: 未知证据类型: " + e.type());
        }
        Map<Severity, Integer> counts = new LinkedHashMap<>();
        if (e.vulnerabilityCounts() != null) {
            e.vulnerabilityCounts().forEach((k, v) -> {
                try {
                    counts.put(Severity.valueOf(k.trim().toUpperCase()), v);
                } catch (IllegalArgumentException ex) {
                    throw new ApiException("INPUT_INVALID: 未知漏洞严重级: " + k);
                }
            });
        }
        return new Evidence(
                e.id(), type, e.boundDigest(), e.createdAt(), e.expiresAt(),
                e.formatVersion() == null ? 0 : e.formatVersion(),
                e.signer(),
                e.attestationTypes() == null ? List.of() : List.copyOf(e.attestationTypes()),
                e.packages() == null ? List.of() : List.copyOf(e.packages()),
                Map.copyOf(counts));
    }

    public PolicyDefinition toPolicy(String name, PolicyDefinitionDto dto) {
        if (dto == null) {
            throw new ApiException("INPUT_INVALID: 策略体为空");
        }
        PolicyScopeDto s = dto.scope();
        PolicyScope scope = s == null ? new PolicyScope("*", "*", "*")
                : new PolicyScope(
                        s.registryPattern() == null ? "*" : s.registryPattern(),
                        s.repositoryPattern() == null ? "*" : s.repositoryPattern(),
                        s.tagPattern() == null ? "*" : s.tagPattern());
        List<PolicyRule> rules = new ArrayList<>();
        if (dto.rules() != null) {
            for (PolicyRuleDto r : dto.rules()) {
                rules.add(toRule(r));
            }
        }
        return new PolicyDefinition(
                name,
                dto.version() == null ? 0 : dto.version(),
                !Boolean.FALSE.equals(dto.enabled()),
                dto.priority() == null ? 1000 : dto.priority(),
                scope,
                List.copyOf(rules));
    }

    private PolicyRule toRule(PolicyRuleDto r) {
        RuleEffect effect;
        try {
            effect = RuleEffect.valueOf(r.effect() == null ? "" : r.effect().trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new ApiException("INPUT_INVALID: 规则 effect 非法: " + r.effect());
        }
        return new PolicyRule(
                r.id(),
                r.description(),
                r.priority() == null ? 1000 : r.priority(),
                effect,
                toConstraints(r.constraints()));
    }

    private RuleConstraints toConstraints(RuleConstraintsDto c) {
        if (c == null) {
            return new RuleConstraints(null, null, null, null, null, null, null, null);
        }
        Severity max = null;
        if (c.maxSeverity() != null && !c.maxSeverity().isBlank()) {
            try {
                max = Severity.valueOf(c.maxSeverity().trim().toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new ApiException("INPUT_INVALID: maxSeverity 非法: " + c.maxSeverity());
            }
        }
        Duration age = c.maxEvidenceAgeSeconds() == null ? null : Duration.ofSeconds(c.maxEvidenceAgeSeconds());
        return new RuleConstraints(
                c.requireSbom(),
                c.requireVulnScan(),
                max,
                c.requireSignature(),
                c.trustedSigners(),
                c.requiredAttestations(),
                age,
                c.forbiddenPackages());
    }

    public EvaluationResponseDto toResponse(String requestId, AdmissionResult r) {
        List<Map<String, Object>> hits = new ArrayList<>();
        for (RuleHit h : r.ruleHits()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("policyName", h.policyName());
            m.put("policyVersion", h.policyVersion());
            m.put("ruleId", h.ruleId());
            m.put("priority", h.priority());
            m.put("effect", h.effect().name());
            m.put("satisfied", h.satisfied());
            m.put("findings", h.findings().stream().map(this::findingMap).toList());
            hits.add(m);
        }
        return new EvaluationResponseDto(
                requestId,
                r.imageReference(),
                r.digest(),
                r.decision().name(),
                r.reason() == null ? null : r.reason().name(),
                r.message(),
                r.policySnapshotVersion(),
                hits,
                r.evidenceIds(),
                r.cacheKey(),
                r.fromCache(),
                r.evaluatedAt());
    }

    private Map<String, Object> findingMap(DenyFinding f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("reason", f.reason().name());
        m.put("detail", f.detail());
        m.put("evidenceId", f.evidenceId());
        return m;
    }
}
