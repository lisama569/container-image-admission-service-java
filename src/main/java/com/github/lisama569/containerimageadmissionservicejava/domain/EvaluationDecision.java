package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

/**
 * 可解释的准入结论。
 */
public record EvaluationDecision(
        Verdict verdict,
        DenyReason denyReason,
        String imageRef,
        long policyVersion,
        List<String> matchedRuleIds,
        List<String> evidenceIds,
        String explanation) {

    public enum Verdict {
        ALLOW, DENY
    }

    public static EvaluationDecision allow(String imageRef, long policyVersion,
                                           List<String> matchedRuleIds, List<String> evidenceIds,
                                           String explanation) {
        return new EvaluationDecision(Verdict.ALLOW, null, imageRef, policyVersion,
                matchedRuleIds, evidenceIds, explanation);
    }

    public static EvaluationDecision deny(DenyReason reason, String imageRef, long policyVersion,
                                          List<String> matchedRuleIds, List<String> evidenceIds,
                                          String explanation) {
        return new EvaluationDecision(Verdict.DENY, reason, imageRef, policyVersion,
                matchedRuleIds, evidenceIds, explanation);
    }
}
