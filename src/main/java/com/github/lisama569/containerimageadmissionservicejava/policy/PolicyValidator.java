package com.github.lisama569.containerimageadmissionservicejava.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;

/**
 * 策略字段合法性校验。返回全部错误描述（空列表表示合法），
 * 非法策略一律拒绝写入，绝不静默忽略。
 */
@Component
public class PolicyValidator {

    public List<String> validate(PolicyDefinition policy) {
        List<String> errors = new ArrayList<>();
        if (policy == null) {
            errors.add("策略不能为空");
            return errors;
        }
        if (policy.name() == null || policy.name().isBlank()) {
            errors.add("策略名称不能为空");
        }
        if (policy.version() < 1) {
            errors.add("策略版本必须 >= 1: " + policy.name());
        }
        if (policy.priority() < 0) {
            errors.add("策略优先级不能为负: " + policy.name());
        }
        List<PolicyRule> rules = policy.rules();
        if (rules == null || rules.isEmpty()) {
            errors.add("策略至少需要一条规则: " + policy.name());
            return errors;
        }
        Set<String> ids = new HashSet<>();
        for (PolicyRule rule : rules) {
            if (rule == null) {
                errors.add("策略 " + policy.name() + " 包含 null 规则");
                continue;
            }
            if (rule.id() == null || rule.id().isBlank()) {
                errors.add("策略 " + policy.name() + " 存在无 id 的规则");
            } else if (!ids.add(rule.id())) {
                errors.add("策略 " + policy.name() + " 规则 id 重复: " + rule.id());
            }
            if (rule.effect() == null) {
                errors.add("规则 " + rule.id() + " 的 effect 缺失");
            }
            if (rule.priority() < 0) {
                errors.add("规则 " + rule.id() + " 的优先级不能为负");
            }
            validateConstraints(policy.name(), rule, errors);
        }
        return errors;
    }

    private void validateConstraints(String policyName, PolicyRule rule, List<String> errors) {
        RuleConstraints c = rule.constraints();
        if (c == null) {
            errors.add("规则 " + policyName + "/" + rule.id() + " 的 constraints 缺失");
            return;
        }
        if (c.maxEvidenceAge() != null && (c.maxEvidenceAge().isNegative() || c.maxEvidenceAge().isZero())) {
            errors.add("规则 " + policyName + "/" + rule.id() + " 的 maxEvidenceAge 必须为正");
        }
        if (c.trustedSigners() != null && c.trustedSigners().stream().anyMatch(s -> s == null || s.isBlank())) {
            errors.add("规则 " + policyName + "/" + rule.id() + " 的 trustedSigners 含空白项");
        }
        if (c.requiredAttestations() != null && c.requiredAttestations().stream().anyMatch(s -> s == null || s.isBlank())) {
            errors.add("规则 " + policyName + "/" + rule.id() + " 的 requiredAttestations 含空白项");
        }
        if (c.forbiddenPackages() != null && c.forbiddenPackages().stream().anyMatch(s -> s == null || s.isBlank())) {
            errors.add("规则 " + policyName + "/" + rule.id() + " 的 forbiddenPackages 含空白项");
        }
    }
}
