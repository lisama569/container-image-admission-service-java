package com.github.lisama569.containerimageadmissionservicejava.web;

import com.github.lisama569.containerimageadmissionservicejava.exception.InvalidCandidatePolicyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.Map;

/**
 * 接口层错误分类：候选策略本身填错（400 + INVALID_CANDIDATE_POLICY）
 * 与其他请求问题、镜像准入拒绝明确区分。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    /** 候选策略/例外不合法：400，错误类型与逐项问题可程序化区分。 */
    @ExceptionHandler(InvalidCandidatePolicyException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidCandidate(InvalidCandidatePolicyException e) {
        return ResponseEntity.badRequest().body(Map.of(
                "errorType", "INVALID_CANDIDATE_POLICY",
                "errors", e.errors()));
    }

    /** 参数非法（如例外已到期、id 重复、无可回滚快照等）：400。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of(
                "errorType", "INVALID_ARGUMENT",
                "errors", List.of(e.getMessage())));
    }

    /** 状态不允许（如没有可回滚快照、没有暂存候选）：409。 */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "errorType", "ILLEGAL_STATE",
                "errors", List.of(e.getMessage())));
    }
}
