package com.github.lisama569.containerimageadmissionservicejava.exception;

import java.util.List;

/**
 * 候选策略不合法时抛出，错误可与镜像准入拒绝原因明确区分。
 */
public class InvalidCandidatePolicyException extends RuntimeException {

    private final List<String> errors;

    public InvalidCandidatePolicyException(List<String> errors) {
        super("candidate policy is invalid: " + errors);
        this.errors = List.copyOf(errors);
    }

    public List<String> errors() {
        return errors;
    }
}
