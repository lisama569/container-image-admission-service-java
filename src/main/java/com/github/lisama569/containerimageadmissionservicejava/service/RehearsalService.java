package com.github.lisama569.containerimageadmissionservicejava.service;

import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.domain.RehearsalReport;
import com.github.lisama569.containerimageadmissionservicejava.policy.CandidatePolicyValidator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 预演服务：拿尚未生效的候选策略对一批镜像“如果按这份策略判”做对比。
 *
 * <p>语义保证：
 * <ul>
 *   <li>候选策略先经 {@link CandidatePolicyValidator} 校验，不合法当场抛
 *       {@code InvalidCandidatePolicyException}（可与准入拒绝原因区分），不悄悄放过；</li>
 *   <li>预演只走 {@link AdmissionService#evaluateWith}，不读/不写线上评估缓存，
 *       不产生审计记录，不影响线上判定；</li>
 *   <li>候选策略未发布，不分配线上版本号；候选侧结论的 policyVersion 标记为
 *       {@code -当前版本} 以便和正式结论区分；</li>
 *   <li>临时例外对基线与候选两侧同样生效（例外独立于策略版本），
 *       因此报告差异只反映策略本身变化。</li>
 * </ul>
 */
@Service
public class RehearsalService {

    private static final Logger log = LoggerFactory.getLogger(RehearsalService.class);

    private final AdmissionService admissionService;
    private final PolicyStore policyStore;
    private final CandidatePolicyValidator candidatePolicyValidator;

    public RehearsalService(AdmissionService admissionService, PolicyStore policyStore,
                            CandidatePolicyValidator candidatePolicyValidator) {
        this.admissionService = admissionService;
        this.policyStore = policyStore;
        this.candidatePolicyValidator = candidatePolicyValidator;
    }

    /**
     * 对一批请求按候选策略做预演对比。
     *
     * @param candidate 候选策略（尚未生效）
     * @param requests  要预演的一批评估请求
     * @return 变化前后对比报告
     */
    public RehearsalReport rehearse(List<Policy> candidate, List<EvaluationRequest> requests) {
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(requests, "requests");
        // 当场校验，全部问题一次性给出，与准入拒绝原因明确区分
        candidatePolicyValidator.validate(candidate);

        PolicySnapshot currentSnapshot = policyStore.snapshot();
        long currentVersion = currentSnapshot.version();
        // 候选快照使用负数版本标记“尚未生效的预演”，绝不与线上版本混淆
        PolicySnapshot candidateSnapshot = new PolicySnapshot(-currentVersion, List.copyOf(candidate));
        String candidateLabel = "candidate@rehearsal-" + currentVersion;

        List<RehearsalReport.ImageChange> changes = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        for (EvaluationRequest request : requests) {
            EvaluationDecision before = admissionService.evaluateWith(request, currentSnapshot);
            EvaluationDecision after = admissionService.evaluateWith(request, candidateSnapshot);
            if (sameOutcome(before, after)) {
                unchanged.add(before.imageRef());
            } else {
                changes.add(new RehearsalReport.ImageChange(before.imageRef(), before, after));
                log.info("rehearsal change image={} {}({}) -> {}({}) rulesBefore={} rulesAfter={}",
                        before.imageRef(),
                        before.verdict(), before.denyReason(),
                        after.verdict(), after.denyReason(),
                        before.matchedRuleIds(), after.matchedRuleIds());
            }
        }
        log.info("rehearsal complete currentVersion={} evaluated={} changed={} unchanged={}",
                currentVersion, requests.size(), changes.size(), unchanged.size());
        return new RehearsalReport(currentVersion, candidateLabel, List.copyOf(changes),
                List.copyOf(unchanged));
    }

    /** 结论是否一致：判定（ALLOW/DENY 及拒绝原因）相同即视为结论不变。 */
    private boolean sameOutcome(EvaluationDecision a, EvaluationDecision b) {
        return a.verdict() == b.verdict() && a.denyReason() == b.denyReason();
    }
}
