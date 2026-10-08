package com.github.lisama569.containerimageadmissionservicejava.service;

import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.domain.PreviewItem;
import com.github.lisama569.containerimageadmissionservicejava.domain.PreviewReport;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 策略预演服务。
 *
 * <p>用一份<strong>尚未生效</strong>的候选策略，对指定的一批评估目标做“假设性”评估，
 * 逐个对比当前线上结论与候选策略下的结论（结论从什么变成什么）。
 *
 * <p>隔离保证：
 * <ul>
 *   <li>候选策略先经 {@link PolicyValidator} 完整校验，非法时抛
 *       {@link com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidationException}，
 *       当场、整体拒绝，绝不静默放过；</li>
 *   <li>预演通过 {@link AdmissionService#evaluateSilently} 计算，
 *       不读/写线上评估缓存、不写审计日志——只看结果，不影响线上判定、不留正式判定记录；</li>
 *   <li>候选快照的版本号取 {@code 0}，与任何真实线上版本都不会混淆。</li>
 * </ul>
 */
@Service
public class PolicyPreviewService {

    private static final Logger log = LoggerFactory.getLogger(PolicyPreviewService.class);

    private final AdmissionService admissionService;
    private final PolicyStore policyStore;
    private final PolicyValidator validator;

    public PolicyPreviewService(AdmissionService admissionService, PolicyStore policyStore,
                                PolicyValidator validator) {
        this.admissionService = admissionService;
        this.policyStore = policyStore;
        this.validator = validator;
    }

    /**
     * 对一批评估目标按候选策略预演。
     *
     * @param candidate 候选策略（必须通过校验）
     * @param targets   待预演的评估目标（镜像 + 解析摘要 + 证据，与真实评估同构）
     * @return 逐镜像结论变化报告
     */
    public PreviewReport preview(List<Policy> candidate, List<EvaluationRequest> targets) {
        validator.validate(candidate);
        if (targets == null || targets.isEmpty()) {
            throw new IllegalArgumentException("预演镜像列表不能为空");
        }
        PolicySnapshot currentSnapshot = policyStore.snapshot();
        // 候选快照版本号固定为 0：明确标识“尚未生效的草稿”，不与线上版本混淆
        PolicySnapshot candidateSnapshot = new PolicySnapshot(0L, List.copyOf(candidate));

        List<PreviewItem> items = new ArrayList<>();
        int changedCount = 0;
        for (EvaluationRequest original : targets) {
            String canonical = canonicalRef(original.imageRef());
            // 预演请求带独立 requestId；evaluateSilently 不写审计，故不会产生正式记录
            EvaluationRequest silentRequest = new EvaluationRequest(
                    "preview-" + UUID.randomUUID(), original.imageRef(),
                    original.resolvedDigest(),
                    original.evidenceList() != null ? original.evidenceList() : List.of());

            EvaluationDecision current =
                    admissionService.evaluateSilently(silentRequest, currentSnapshot);
            EvaluationDecision projected =
                    admissionService.evaluateSilently(silentRequest, candidateSnapshot);

            // 仅当结论（verdict，或同为 DENY 时的拒绝原因）不同才算“结论变化”
            boolean changed = verdictChanged(current, projected);
            if (changed) {
                changedCount++;
            }
            items.add(new PreviewItem(canonical,
                    current.verdict(), current.denyReason(),
                    projected.verdict(), projected.denyReason(), changed));
        }
        log.info("policy preview currentVersion={} images={} changed={}",
                currentSnapshot.version(), items.size(), changedCount);
        return new PreviewReport(0L, currentSnapshot.version(), List.copyOf(items));
    }

    /** 结论是否变化：verdict 变化，或同为 DENY 但拒绝原因变化。 */
    private boolean verdictChanged(EvaluationDecision current, EvaluationDecision projected) {
        if (current.verdict() != projected.verdict()) {
            return true;
        }
        return current.verdict() == EvaluationDecision.Verdict.DENY
                && current.denyReason() != projected.denyReason();
    }

    private String canonicalRef(String rawRef) {
        try {
            return ImageRef.parse(rawRef).canonical();
        } catch (IllegalArgumentException e) {
            return rawRef;
        }
    }
}
