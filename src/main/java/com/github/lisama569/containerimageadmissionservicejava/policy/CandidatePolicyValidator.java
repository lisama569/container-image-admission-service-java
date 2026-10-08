package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.exception.InvalidCandidatePolicyException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 候选策略校验：预演/发布前对尚未生效的策略做结构性校验。
 *
 * <p>校验不通过时收集全部问题并抛 {@link InvalidCandidatePolicyException}，
 * 与镜像准入的 {@code DenyReason} 明确区分，绝不悄悄放过。
 *
 * <p>校验项：
 * <ol>
 *   <li>策略列表非空；</li>
 *   <li>策略 name 非空且不重复；</li>
 *   <li>每条规则 ruleId 非空且全局唯一；</li>
 *   <li>scopePattern 非空；</li>
 *   <li>effect 非空（ALLOW/DENY）；</li>
 *   <li>requiredEvidence 列表中证据类型非空且不重复；</li>
 *   <li>每条策略至少有一条规则（否则该策略永远不生效，多半是填错）。</li>
 * </ol>
 */
@Component
public class CandidatePolicyValidator {

    /** 校验候选策略；不合法时抛出带全部问题列表的异常。 */
    public void validate(List<Policy> candidate) {
        List<String> errors = new ArrayList<>();
        if (candidate == null || candidate.isEmpty()) {
            throw new InvalidCandidatePolicyException(List.of("策略列表为空：至少需要一条策略"));
        }
        Set<String> policyNames = new HashSet<>();
        Set<String> ruleIds = new HashSet<>();
        for (int i = 0; i < candidate.size(); i++) {
            Policy policy = candidate.get(i);
            String policyDesc = "第 " + i + " 个策略";
            if (policy == null) {
                errors.add(policyDesc + " 为 null");
                continue;
            }
            policyDesc = "策略[" + policy.name() + "]";
            if (policy.name() == null || policy.name().isBlank()) {
                errors.add(policyDesc + " 缺少 name");
            } else if (!policyNames.add(policy.name())) {
                errors.add(policyDesc + " name 重复");
            }
            List<Policy.PolicyRule> rules = policy.rules();
            if (rules == null || rules.isEmpty()) {
                errors.add(policyDesc + " 不包含任何规则");
                continue;
            }
            for (Policy.PolicyRule rule : rules) {
                if (rule == null) {
                    errors.add(policyDesc + " 中存在 null 规则");
                    continue;
                }
                String ruleDesc = policyDesc + " 的规则[" + rule.ruleId() + "]";
                if (rule.ruleId() == null || rule.ruleId().isBlank()) {
                    errors.add(policyDesc + " 中存在缺少 ruleId 的规则");
                } else if (!ruleIds.add(rule.ruleId())) {
                    errors.add(ruleDesc + " ruleId 与其他规则重复");
                }
                if (rule.scopePattern() == null || rule.scopePattern().isBlank()) {
                    errors.add(ruleDesc + " 缺少 scopePattern");
                }
                if (rule.effect() == null) {
                    errors.add(ruleDesc + " 缺少 effect（必须为 ALLOW 或 DENY）");
                }
                List<Evidence.EvidenceType> required = rule.requiredEvidence();
                if (required == null) {
                    errors.add(ruleDesc + " requiredEvidence 为 null");
                } else {
                    Set<Evidence.EvidenceType> types = new HashSet<>();
                    for (Evidence.EvidenceType type : required) {
                        if (type == null) {
                            errors.add(ruleDesc + " requiredEvidence 含 null 类型");
                        } else if (!types.add(type)) {
                            errors.add(ruleDesc + " requiredEvidence 中类型重复: " + type);
                        }
                    }
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new InvalidCandidatePolicyException(errors);
        }
    }
}
