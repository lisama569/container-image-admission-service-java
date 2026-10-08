package com.github.lisama569.containerimageadmissionservicejava.web;

import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.Map;

/**
 * REST 层异常映射。
 *
 * <p>把“候选策略/例外本身填得不对”的前置校验失败（400）与线上评估拒绝
 * （422，携带可区分 {@code denyReason}）区分开；发布/回滚状态错误返回 409。
 * 非法输入绝不静默放过，反馈中携带全部可定位的问题。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /** 候选策略校验不通过 → 400，body 中含全部具体问题。 */
    @ExceptionHandler(PolicyValidationException.class)
    public ResponseEntity<Map<String, Object>> handlePolicyValidation(PolicyValidationException ex) {
        log.info("reject invalid candidate policy issues={}", ex.issues());
        return ResponseEntity.badRequest().body(Map.of(
                "error", "INVALID_CANDIDATE_POLICY",
                "issues", ex.issues()));
    }

    /** 非法参数（例外非法、预演镜像为空等）→ 400。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "error", "INVALID_REQUEST",
                "issues", List.of(ex.getMessage())));
    }

    /** 发布/回滚状态错误（无草稿/无可回滚目标）→ 409。 */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "error", "ILLEGAL_RELEASE_STATE",
                "issues", List.of(ex.getMessage())));
    }
}
