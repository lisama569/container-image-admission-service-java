package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

/**
 * 策略：包含一组有序规则，带版本号。
 */
public record Policy(String name, long version, List<PolicyRule> rules) {

    public record PolicyRule(
            String ruleId,
            String scopePattern,
            int priority,
            Effect effect,
            List<Evidence.EvidenceType> requiredEvidence) {
    }

    public enum Effect {
        ALLOW, DENY
    }
}
