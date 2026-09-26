package com.github.lisama569.containerimageadmissionservicejava.eval;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.DecisionOutcome;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyFinding;
import com.github.lisama569.containerimageadmissionservicejava.domain.DenyReasonCode;
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
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.ScopeMatcher;

/**
 * 准入判定核心。所有判定都基于调用方传入的同一个不可变 {@link PolicySnapshot}。
 *
 * <p>判定顺序（前面的失败直接产生确定的拒绝原因，不静默放行）：
 * <ol>
 *   <li>输入与镜像摘要归一化校验；</li>
 *   <li>标签固定（tag-only 引用按标签漂移拒绝）、清单摘要一致性与清单完整性；</li>
 *   <li>证据与镜像摘要绑定校验（不一致立即拒绝）；</li>
 *   <li>策略作用域解析：无任何策略 → POLICY_NOT_FOUND；有策略但均不命中 → NO_RULE_MATCHED；</li>
 *   <li>收集命中策略的全部规则，取最高优先级组（priority 数值最小）；</li>
 *   <li>组内评估：DENY 规则为否决权（约束成立即否决），ALLOW 规则为必须全部满足的要求；
 *       同优先级内 ALLOW 与 DENY 同时成立 → POLICY_CONFLICT，fail-closed。</li>
 * </ol>
 */
@Component
public class PolicyEvaluator {

    private static final Logger log = LoggerFactory.getLogger(PolicyEvaluator.class);

    /** 当前支持的证据格式版本，低于该版本视为旧格式证据（EVIDENCE_STALE）。 */
    public static final int SUPPORTED_EVIDENCE_FORMAT = 1;

    private record ResolvedRule(PolicyDefinition policy, PolicyRule rule) {
    }

    private final ScopeMatcher scopeMatcher;
    private final DigestNormalizer digestNormalizer;
    private final Clock clock;

    public PolicyEvaluator(ScopeMatcher scopeMatcher, DigestNormalizer digestNormalizer, Clock clock) {
        this.scopeMatcher = scopeMatcher;
        this.digestNormalizer = digestNormalizer;
        this.clock = clock;
    }

    public AdmissionResult evaluate(EvaluationInput input, PolicySnapshot snapshot, String cacheKey, boolean fromCache) {
        Instant now = Instant.now(clock);
        ImageRef image = input.image();

        // 1. 基础输入校验
        if (image == null || image.repository() == null || image.repository().isBlank()) {
            return deny(image, null, snapshot, DenyReasonCode.INPUT_INVALID, "镜像标识缺少 repository",
                    List.of(), cacheKey, fromCache, now);
        }

        String requestedDigest = null;
        if (image.digest() != null && !image.digest().isBlank()) {
            try {
                requestedDigest = digestNormalizer.normalize(image.digest());
            } catch (IllegalArgumentException ex) {
                return deny(image, null, snapshot, DenyReasonCode.INPUT_INVALID,
                        "镜像摘要格式非法: " + ex.getMessage(), List.of(), cacheKey, fromCache, now);
            }
        }

        // 2a. 标签漂移：只有 tag、没有 digest 的引用无法固定内容
        if (requestedDigest == null) {
            return deny(image, null, snapshot, DenyReasonCode.TAG_DRIFT,
                    "镜像仅以标签引用而无摘要，无法防止标签漂移", List.of(), cacheKey, fromCache, now);
        }

        // 2b. 清单校验
        ImageManifest manifest = input.manifest();
        if (manifest == null) {
            return deny(image, requestedDigest, snapshot, DenyReasonCode.MANIFEST_INCOMPLETE,
                    "缺少镜像清单", List.of(), cacheKey, fromCache, now);
        }
        String manifestDigest;
        try {
            manifestDigest = digestNormalizer.normalize(manifest.digest());
        } catch (IllegalArgumentException ex) {
            return deny(image, requestedDigest, snapshot, DenyReasonCode.INPUT_INVALID,
                    "清单摘要格式非法: " + ex.getMessage(), List.of(), cacheKey, fromCache, now);
        }
        if (!manifestDigest.equals(requestedDigest)) {
            return deny(image, requestedDigest, snapshot, DenyReasonCode.EVIDENCE_DIGEST_MISMATCH,
                    "清单摘要 " + manifestDigest + " 与请求镜像摘要 " + requestedDigest + " 不一致",
                    List.of(), cacheKey, fromCache, now);
        }
        if (manifest.entries() == null || manifest.entries().isEmpty()) {
            return deny(image, requestedDigest, snapshot, DenyReasonCode.MANIFEST_INCOMPLETE,
                    "清单内容为空", List.of(), cacheKey, fromCache, now);
        }
        for (ManifestEntry entry : manifest.entries()) {
            if (entry == null || entry.name() == null || entry.name().isBlank()
                    || entry.digest() == null || entry.digest().isBlank() || entry.size() == null) {
                return deny(image, requestedDigest, snapshot, DenyReasonCode.MANIFEST_INCOMPLETE,
                        "清单条目不完整（name/digest/size 必填）: " + entry,
                        List.of(), cacheKey, fromCache, now);
            }
            try {
                digestNormalizer.normalize(entry.digest());
            } catch (IllegalArgumentException ex) {
                return deny(image, requestedDigest, snapshot, DenyReasonCode.INPUT_INVALID,
                        "清单条目摘要非法 (" + entry.name() + "): " + ex.getMessage(),
                        List.of(), cacheKey, fromCache, now);
            }
        }

        // 3. 证据绑定校验：所有证据都必须绑定到同一镜像摘要
        List<Evidence> evidences = input.evidences() == null ? List.of() : input.evidences();
        List<String> evidenceIds = evidences.stream().map(Evidence::id).sorted().toList();
        for (Evidence e : evidences) {
            if (e == null || e.id() == null || e.id().isBlank()) {
                return deny(image, requestedDigest, snapshot, DenyReasonCode.INPUT_INVALID,
                        "存在缺少 id 的证据", List.of(), cacheKey, fromCache, now);
            }
            if (e.type() == null) {
                return deny(image, requestedDigest, snapshot, DenyReasonCode.INPUT_INVALID,
                        "证据 " + e.id() + " 缺少 type", List.of(), cacheKey, fromCache, now);
            }
            String bound;
            try {
                bound = digestNormalizer.normalize(e.boundDigest());
            } catch (IllegalArgumentException ex) {
                return deny(image, requestedDigest, snapshot, DenyReasonCode.EVIDENCE_DIGEST_MISMATCH,
                        "证据 " + e.id() + " 绑定摘要非法: " + ex.getMessage(),
                        List.of(), cacheKey, fromCache, now);
            }
            if (!bound.equals(requestedDigest)) {
                return deny(image, requestedDigest, snapshot, DenyReasonCode.EVIDENCE_DIGEST_MISMATCH,
                        "证据 " + e.id() + " 绑定摘要 " + bound + " 与镜像摘要 " + requestedDigest + " 不一致",
                        List.of(), cacheKey, fromCache, now);
            }
        }

        // 4. 策略作用域解析
        List<PolicyDefinition> enabled = snapshot.policies().stream()
                .filter(PolicyDefinition::enabled)
                .toList();
        List<PolicyDefinition> matched = enabled.stream()
                .filter(p -> scopeMatches(p.scope(), image))
                .toList();
        if (enabled.isEmpty()) {
            return deny(image, requestedDigest, snapshot, DenyReasonCode.POLICY_NOT_FOUND,
                    "当前不存在任何已启用策略", List.of(), cacheKey, fromCache, now);
        }
        if (matched.isEmpty()) {
            return deny(image, requestedDigest, snapshot, DenyReasonCode.NO_RULE_MATCHED,
                    "没有任何策略作用域命中该镜像", List.of(), cacheKey, fromCache, now);
        }
        List<String> matchedVersions = matched.stream()
                .map(p -> p.name() + "@v" + p.version())
                .sorted()
                .toList();

        // 5. 汇总规则并选最高优先级组
        List<ResolvedRule> all = new ArrayList<>();
        for (PolicyDefinition p : matched) {
            for (PolicyRule r : p.rules()) {
                all.add(new ResolvedRule(p, r));
            }
        }
        int highestPriority = all.stream().mapToInt(r -> r.rule().priority()).min().orElseThrow();
        List<ResolvedRule> group = all.stream()
                .filter(r -> r.rule().priority() == highestPriority)
                .sorted(Comparator
                        .comparingInt((ResolvedRule r) -> r.policy().priority())
                        .thenComparing(r -> r.policy().name())
                        .thenComparing(r -> r.rule().id()))
                .toList();

        // 6. 组内逐条评估
        List<RuleHit> hits = new ArrayList<>();
        List<ResolvedRule> satisfiedDenies = new ArrayList<>();
        List<ResolvedRule> passingAllows = new ArrayList<>();
        List<DenyFinding> firstAllowFailure = new ArrayList<>();
        for (ResolvedRule rr : group) {
            List<DenyFinding> findings = evaluateConstraints(
                    rr.rule(), rr.rule().constraints(), evidences, now);
            // ALLOW：findings 为空表示要求全部满足；DENY：findings 非空表示否决条件被正向触发
            boolean satisfied = rr.rule().effect() == RuleEffect.DENY ? !findings.isEmpty() : findings.isEmpty();
            hits.add(new RuleHit(rr.policy().name(), rr.policy().version(), rr.rule().id(),
                    rr.rule().priority(), rr.rule().effect(), satisfied, findings));
            if (satisfied && rr.rule().effect() == RuleEffect.DENY) {
                satisfiedDenies.add(rr);
            }
            if (rr.rule().effect() == RuleEffect.ALLOW) {
                if (satisfied) {
                    passingAllows.add(rr);
                } else if (firstAllowFailure.isEmpty()) {
                    firstAllowFailure.addAll(findings);
                }
            }
        }
        long allowCount = group.stream().filter(r -> r.rule().effect() == RuleEffect.ALLOW).count();

        log.info("评估镜像 image={} digest={} policySnapshot={} 命中策略={} 生效优先级={} 规则命中={}",
                image.reference(), requestedDigest, snapshot.snapshotVersion(),
                matchedVersions, highestPriority,
                hits.stream().map(h -> h.policyName() + "/" + h.ruleId()
                        + "(" + h.effect() + "," + (h.satisfied() ? "成立" : "不成立") + ")").toList());

        // 同优先级 ALLOW 与 DENY 同时成立：冲突，fail-closed
        if (!satisfiedDenies.isEmpty() && !passingAllows.isEmpty()) {
            String detail = "同优先级 " + highestPriority + " 内允许规则 "
                    + passingAllows.stream().map(r -> r.policy().name() + "/" + r.rule().id()).toList()
                    + " 与否决规则 "
                    + satisfiedDenies.stream().map(r -> r.policy().name() + "/" + r.rule().id()).toList()
                    + " 同时成立";
            return deny(image, requestedDigest, snapshot, DenyReasonCode.POLICY_CONFLICT, detail,
                    hits, evidenceIds, cacheKey, fromCache, now, matchedVersions);
        }
        if (!satisfiedDenies.isEmpty()) {
            ResolvedRule rr = satisfiedDenies.get(0);
            RuleHit hit = hits.stream()
                    .filter(h -> h.ruleId().equals(rr.rule().id()) && h.policyName().equals(rr.policy().name()))
                    .findFirst().orElse(hits.get(0));
            DenyFinding trigger = hit.findings().isEmpty()
                    ? new DenyFinding(DenyReasonCode.RULE_VIOLATION, "命中否决条件", null)
                    : hit.findings().get(0);
            return deny(image, requestedDigest, snapshot, trigger.reason(),
                    "命中否决规则 " + rr.policy().name() + "/" + rr.rule().id() + ": " + trigger.detail(),
                    hits, evidenceIds, cacheKey, fromCache, now, matchedVersions);
        }
        if (allowCount > 0 && firstAllowFailure.isEmpty()) {
            return allow(image, requestedDigest, snapshot, hits, evidenceIds, cacheKey, fromCache, now,
                    matchedVersions);
        }
        if (allowCount == 0) {
            // 生效组只有 DENY 规则且没有任何一条触发：不构成否决，按无约束适用放行
            return allow(image, requestedDigest, snapshot, hits, evidenceIds, cacheKey, fromCache, now,
                    matchedVersions);
        }
        // ALLOW 规则未能全部满足：按首个具体证据原因拒绝
        DenyFinding first = firstAllowFailure.isEmpty()
                ? new DenyFinding(DenyReasonCode.EVIDENCE_INSUFFICIENT, "证据不足以满足策略要求", null)
                : firstAllowFailure.get(0);
        return deny(image, requestedDigest, snapshot, first.reason(), first.detail(),
                hits, evidenceIds, cacheKey, fromCache, now, matchedVersions);
    }

    private boolean scopeMatches(PolicyScope scope, ImageRef image) {
        return scopeMatcher.matches(scope, image);
    }

    /**
     * 评估一条规则的约束集合，返回导致规则“不成立”的发现（空列表表示规则成立）。
     * <p>语义随规则效果而不同：
     * <ul>
     *   <li>ALLOW 规则：约束是必须全部满足的要求，任一不满足即为不成立（产生具体证据原因）；</li>
     *   <li>DENY 规则：约束是“触发条件”，条件成立时规则成立（产生 RULE_VIOLATION）；
     *       要求类约束（必须存在某证据）在证据缺失时不触发否决，而是视为条件不成立。</li>
     * </ul>
     * 发现按原因排序以保证确定性。
     */
    private List<DenyFinding> evaluateConstraints(PolicyRule rule, RuleConstraints c,
                                                  List<Evidence> evidences, Instant now) {
        List<DenyFinding> findings = new ArrayList<>();
        if (c == null) {
            return findings;
        }
        boolean deny = rule.effect() == RuleEffect.DENY;
        if (Boolean.TRUE.equals(c.requireSbom())) {
            Optional<Evidence> sbom = findUsable(evidences, EvidenceType.SBOM, now, findings,
                    DenyReasonCode.EVIDENCE_MISSING, DenyReasonCode.EVIDENCE_EXPIRED, deny);
            if (deny) {
                // DENY 语义：存在有效 SBOM 即触发否决
                sbom.ifPresent(e -> findings.add(new DenyFinding(DenyReasonCode.RULE_VIOLATION,
                        "发现 SBOM 证据 " + e.id() + "，触发否决规则", e.id())));
            } else if (sbom.isPresent()
                    && (sbom.get().packages() == null || sbom.get().packages().isEmpty())) {
                findings.add(new DenyFinding(DenyReasonCode.EVIDENCE_INSUFFICIENT,
                        "SBOM 证据 " + sbom.get().id() + " 缺少软件成分清单", sbom.get().id()));
            }
        }
        if (Boolean.TRUE.equals(c.requireVulnScan()) || c.maxSeverity() != null) {
            Optional<Evidence> scan = findUsable(evidences, EvidenceType.VULN_SCAN, now, findings,
                    DenyReasonCode.VULN_SCAN_MISSING, DenyReasonCode.VULN_SCAN_MISSING, deny);
            if (scan.isPresent()) {
                if (deny && Boolean.TRUE.equals(c.requireVulnScan()) && c.maxSeverity() == null) {
                    // DENY 语义：存在有效漏洞扫描即触发否决
                    findings.add(new DenyFinding(DenyReasonCode.RULE_VIOLATION,
                            "发现漏洞扫描证据 " + scan.get().id() + "，触发否决规则", scan.get().id()));
                }
                checkVulnCounts(scan.get(), c.maxSeverity(), deny, findings);
            }
        }
        if (Boolean.TRUE.equals(c.requireSignature()) || (c.trustedSigners() != null && !c.trustedSigners().isEmpty())) {
            checkSignature(evidences, c, now, deny, findings);
        }
        if (c.requiredAttestations() != null && !c.requiredAttestations().isEmpty()) {
            checkAttestations(evidences, c, now, deny, findings);
        }
        if (c.maxEvidenceAge() != null) {
            for (Evidence e : evidences) {
                if (e.createdAt() != null && e.createdAt().plus(c.maxEvidenceAge()).isBefore(now)) {
                    findings.add(new DenyFinding(DenyReasonCode.EVIDENCE_EXPIRED,
                            "证据 " + e.id() + " 早于最大允许年龄 " + c.maxEvidenceAge(), e.id()));
                }
            }
        }
        if (c.forbiddenPackages() != null && !c.forbiddenPackages().isEmpty()) {
            for (Evidence sbom : evidences.stream().filter(e -> e.type() == EvidenceType.SBOM).toList()) {
                if (sbom.packages() == null) {
                    continue;
                }
                for (String forbidden : c.forbiddenPackages()) {
                    if (sbom.packages().contains(forbidden)) {
                        findings.add(new DenyFinding(DenyReasonCode.RULE_VIOLATION,
                                "SBOM " + sbom.id() + " 包含禁止软件成分: " + forbidden, sbom.id()));
                    }
                }
            }
        }
        return findings.stream()
                .sorted(Comparator.comparing((DenyFinding f) -> f.reason().name()).thenComparing(DenyFinding::detail))
                .toList();
    }

    /**
     * 查找可用（绑定正确、未过期、格式受支持）的指定类型证据。
     * 不存在 / 过期 / 旧格式会分别产生可区分的发现；存在多个时取最新一个。
     */
    private Optional<Evidence> findUsable(List<Evidence> evidences, EvidenceType type, Instant now,
                                          List<DenyFinding> findings,
                                          DenyReasonCode missingReason, DenyReasonCode expiredReason,
                                          boolean denyRule) {
        List<Evidence> typed = evidences.stream().filter(e -> e.type() == type).toList();
        if (typed.isEmpty()) {
            // DENY 规则：缺少该证据则触发条件不成立，但不应产生“缺失”发现（缺证据不是违规）
            if (!denyRule) {
                findings.add(new DenyFinding(missingReason, "缺少 " + type + " 证据", null));
            }
            return Optional.empty();
        }
        Evidence newest = typed.stream()
                .max(Comparator.comparing(Evidence::createdAt, Comparator.nullsFirst(Comparator.naturalOrder())))
                .orElseThrow();
        if (newest.expiresAt() != null && !newest.expiresAt().isAfter(now)) {
            if (!denyRule) {
                findings.add(new DenyFinding(expiredReason,
                        type + " 证据 " + newest.id() + " 已过期 (" + newest.expiresAt() + ")", newest.id()));
            }
            return Optional.empty();
        }
        if (newest.formatVersion() < SUPPORTED_EVIDENCE_FORMAT) {
            if (!denyRule) {
                findings.add(new DenyFinding(DenyReasonCode.EVIDENCE_STALE,
                        type + " 证据 " + newest.id() + " 使用已弃用的旧格式版本 "
                                + newest.formatVersion() + "，支持的最低版本为 " + SUPPORTED_EVIDENCE_FORMAT,
                        newest.id()));
            }
            return Optional.empty();
        }
        return Optional.of(newest);
    }

    private void checkVulnCounts(Evidence scan, Severity maxSeverity, boolean denyRule,
                                 List<DenyFinding> findings) {
        Map<Severity, Integer> counts = scan.vulnerabilityCounts();
        if (counts == null || counts.isEmpty()) {
            // DENY 规则下无计数意味着“无可否决依据”，条件不成立；ALLOW 规则下是证据不足。
            if (!denyRule) {
                findings.add(new DenyFinding(DenyReasonCode.VULN_SCAN_MISSING,
                        "漏洞扫描证据 " + scan.id() + " 不包含计数结果", scan.id()));
            }
            return;
        }
        Severity worst = Severity.NONE;
        for (Map.Entry<Severity, Integer> e : counts.entrySet())
            if (e.getValue() != null && e.getValue() > 0 && e.getKey().level() > worst.level()) {
                worst = e.getKey();
            }
        if (maxSeverity != null) {
            boolean exceeds = worst.level() > maxSeverity.level();
            boolean reaches = worst.level() >= maxSeverity.level() && worst != Severity.NONE;
            if (denyRule) {
                // DENY 触发条件：出现达到或高于阈值的漏洞时规则成立（RULE_VIOLATION）
                if (reaches) {
                    findings.add(new DenyFinding(DenyReasonCode.RULE_VIOLATION,
                            "最高漏洞严重级 " + worst + " 达到/超过否决阈值 " + maxSeverity
                                    + "（扫描证据 " + scan.id() + "）", scan.id()));
                }
            } else if (exceeds) {
                findings.add(new DenyFinding(DenyReasonCode.VULN_THRESHOLD_EXCEEDED,
                        "最高漏洞严重级 " + worst + " 超出策略上限 " + maxSeverity + "（扫描证据 " + scan.id() + "）",
                        scan.id()));
            }
        }
    }

    private void checkSignature(List<Evidence> evidences, RuleConstraints c, Instant now,
                                boolean denyRule, List<DenyFinding> findings) {
        List<Evidence> sigs = evidences.stream().filter(e -> e.type() == EvidenceType.SIGNATURE).toList();
        if (sigs.isEmpty()) {
            // DENY 规则不依赖签名存在与否进行否决：缺失 = 条件不成立，不产生发现
            if (!denyRule) {
                findings.add(new DenyFinding(DenyReasonCode.SIGNATURE_MISSING, "缺少签名证据", null));
            }
            return;
        }
        boolean anyValid = false;
        boolean anySpecificFailure = false;
        for (Evidence sig : sigs) {
            if (sig.formatVersion() < SUPPORTED_EVIDENCE_FORMAT) {
                if (!denyRule) {
                    findings.add(new DenyFinding(DenyReasonCode.EVIDENCE_STALE,
                            "签名证据 " + sig.id() + " 为旧格式版本 " + sig.formatVersion(), sig.id()));
                    anySpecificFailure = true;
                }
                continue;
            }
            if (sig.expiresAt() != null && !sig.expiresAt().isAfter(now)) {
                if (!denyRule) {
                    findings.add(new DenyFinding(DenyReasonCode.SIGNATURE_EXPIRED,
                            "签名 " + sig.id() + " 已过期 (" + sig.expiresAt() + ")", sig.id()));
                    anySpecificFailure = true;
                }
                continue;
            }
            boolean trusted = c.trustedSigners() == null || c.trustedSigners().isEmpty()
                    || (sig.signer() != null && c.trustedSigners().contains(sig.signer()));
            if (!trusted) {
                if (!denyRule) {
                    findings.add(new DenyFinding(DenyReasonCode.SIGNATURE_UNTRUSTED_SIGNER,
                            "签名者 " + sig.signer() + " 不在信任列表 " + c.trustedSigners()
                                    + "（签名 " + sig.id() + "）", sig.id()));
                    anySpecificFailure = true;
                }
                continue;
            }
            anyValid = true;
        }
        if (!anyValid && !denyRule && !anySpecificFailure) {
            findings.add(new DenyFinding(DenyReasonCode.SIGNATURE_MISSING, "缺少有效签名证据", null));
        }
    }

    private void checkAttestations(List<Evidence> evidences, RuleConstraints c, Instant now,
                                   boolean denyRule, List<DenyFinding> findings) {
        List<Evidence> atts = evidences.stream().filter(e -> e.type() == EvidenceType.ATTESTATION).toList();
        if (atts.isEmpty()) {
            if (!denyRule) {
                findings.add(new DenyFinding(DenyReasonCode.ATTESTATION_MISSING, "缺少证明材料", null));
            }
            return;
        }
        List<Evidence> usable = new ArrayList<>();
        for (Evidence a : atts) {
            if (a.formatVersion() < SUPPORTED_EVIDENCE_FORMAT) {
                if (!denyRule) {
                    findings.add(new DenyFinding(DenyReasonCode.EVIDENCE_STALE,
                            "证明材料 " + a.id() + " 为旧格式版本 " + a.formatVersion(), a.id()));
                }
                continue;
            }
            if (a.expiresAt() != null && !a.expiresAt().isAfter(now)) {
                if (!denyRule) {
                    findings.add(new DenyFinding(DenyReasonCode.EVIDENCE_EXPIRED,
                            "证明材料 " + a.id() + " 已过期 (" + a.expiresAt() + ")", a.id()));
                }
                continue;
            }
            usable.add(a);
        }
        if (denyRule) {
            // DENY 触发条件：出现覆盖任一指定类型的证明
            for (String required : c.requiredAttestations()) {
                boolean covered = usable.stream().anyMatch(a -> a.attestationTypes() != null
                        && a.attestationTypes().contains(required));
                if (covered) {
                    findings.add(new DenyFinding(DenyReasonCode.RULE_VIOLATION,
                            "存在触发否决的证明类型: " + required, null));
                }
            }
            return;
        }
        for (String required : c.requiredAttestations()) {
            boolean covered = usable.stream().anyMatch(a -> a.attestationTypes() != null
                    && a.attestationTypes().contains(required));
            if (!covered) {
                findings.add(new DenyFinding(DenyReasonCode.ATTESTATION_TYPE_MISSING,
                        "没有可用证明材料覆盖必需类型: " + required, null));
            }
        }
    }

    private AdmissionResult allow(ImageRef image, String digest, PolicySnapshot snapshot, List<RuleHit> hits,
                                  List<String> evidenceIds, String cacheKey, boolean fromCache, Instant at,
                                  List<String> matchedVersions) {
        return new AdmissionResult(image.reference(), digest, DecisionOutcome.ALLOW, null,
                "符合命中策略的全部允许要求", snapshot.snapshotVersion(), matchedVersions,
                List.copyOf(hits), evidenceIds, cacheKey, fromCache, at);
    }

    private AdmissionResult deny(ImageRef image, String digest, PolicySnapshot snapshot,
                                 DenyReasonCode reason, String message, List<RuleHit> hits,
                                 String cacheKey, boolean fromCache, Instant at) {
        return deny(image, digest, snapshot, reason, message, hits, List.of(), cacheKey, fromCache, at, List.of());
    }

    private AdmissionResult deny(ImageRef image, String digest, PolicySnapshot snapshot,
                                 DenyReasonCode reason, String message, List<RuleHit> hits,
                                 List<String> evidenceIds, String cacheKey, boolean fromCache, Instant at,
                                 List<String> matchedVersions) {
        String ref = image == null ? "<unknown>" : image.reference();
        log.info("拒绝镜像 image={} digest={} policySnapshot={} reason={} 证据={} 详情={}",
                ref, digest, snapshot.snapshotVersion(), reason, evidenceIds, message);
        return new AdmissionResult(ref, digest, DecisionOutcome.DENY, reason, message,
                snapshot.snapshotVersion(), matchedVersions, List.copyOf(hits), evidenceIds,
                cacheKey, fromCache, at);
    }
}
