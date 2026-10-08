package com.github.lisama569.containerimageadmissionservicejava.policy;

import java.util.List;

/**
 * 候选策略校验不通过：携带全部可区分的具体问题，
 * 与普通评估拒绝（{@code denyReason}）区分开——非法候选策略必须当场拒绝，不得静默放过。
 */
public class PolicyValidationException extends RuntimeException {

    private final List<String> issues;

    public PolicyValidationException(List<String> issues) {
        super("候选策略校验不通过: " + String.join("; ", issues));
        this.issues = List.copyOf(issues);
    }

    /** 全部校验问题（至少一条）。 */
    public List<String> issues() {
        return issues;
    }
}
