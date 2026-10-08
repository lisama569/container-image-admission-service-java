package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 候选策略校验器。
 *
 * <p>与线上评估的拒绝原因不同：候选策略本身填得不对属于“发布前置校验失败”，
 * 必须当场、整体拒绝（{@link PolicyValidationException}），而不是带着问题上线。
 * 所有问题一次性收集报出，方便调用方一次修完；任何一条不通过都不得暂存/发布。
 */
@Component
public class PolicyValidator {

    /**
     * 校验候选策略列表；不通过时抛出携带全部问题的 {@link PolicyValidationException}。
     */
    public void validate(List<Policy> policies) {
        List<String> issues = new ArrayList<>();
        if (policies == null || policies.isEmpty()) {
            throw new PolicyValidationException(List.of("策略列表为空：至少需要一条策略"));
        }
        Set<String> ruleIds = new HashSet<>();
        for (int i = 0; i < policies.size(); i++) {
            Policy policy = policies.get(i);
            String pLabel = "策略[" + i + "]";
            if (policy == null) {
                issues.add(pLabel + " 为 null");
                continue;
            }
            if (policy.name() == null || policy.name().isBlank()) {
                issues.add(pLabel + " 缺少名称");
            }
            if (policy.rules() == null || policy.rules().isEmpty()) {
                issues.add(pLabel + "（name=" + policy.name() + "）不包含任何规则");
                continue;
            }
            for (Policy.PolicyRule rule : policy.rules()) {
                if (rule == null) {
                    issues.add(pLabel + " 含 null 规则");
                    continue;
                }
                String rLabel = "规则[" + rule.ruleId() + "]";
                if (rule.ruleId() == null || rule.ruleId().isBlank()) {
                    issues.add(pLabel + " 中存在缺少 ruleId 的规则");
                } else if (!ruleIds.add(rule.ruleId())) {
                    issues.add(pLabel + " 的 " + rLabel + " ruleId 重复（确定性排序要求 ruleId 唯一）");
                }
                if (rule.scopePattern() == null || rule.scopePattern().isBlank()) {
                    issues.add(rLabel + " 缺少 scopePattern");
                }
                if (rule.effect() == null) {
                    issues.add(rLabel + " 缺少 effect（ALLOW/DENY）");
                }
                if (rule.requiredEvidence() != null) {
                    for (Evidence.EvidenceType type : rule.requiredEvidence()) {
                        if (type == null) {
                            issues.add(rLabel + " 的 requiredEvidence 含 null 元素");
                        }
                    }
                }
            }
        }
        if (!issues.isEmpty()) {
            throw new PolicyValidationException(issues);
        }
    }
}
