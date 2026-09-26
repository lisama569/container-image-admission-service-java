package com.github.lisama569.containerimageadmissionservicejava.web;

import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.github.lisama569.containerimageadmissionservicejava.common.ApiException;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.ErrorDto;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final Clock clock;

    public GlobalExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorDto> handleApi(ApiException ex) {
        String code = ex.getMessage() == null ? "ERROR"
                : ex.getMessage().contains(":") ? ex.getMessage().substring(0, ex.getMessage().indexOf(':'))
                : "ERROR";
        HttpStatus status = switch (code) {
            case "POLICY_NOT_FOUND" -> HttpStatus.NOT_FOUND;
            case "POLICY_INVALID", "INPUT_INVALID" -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.UNPROCESSABLE_ENTITY;
        };
        log.warn("请求被拒绝 code={} message={}", code, ex.getMessage());
        return ResponseEntity.status(status).body(new ErrorDto(code, ex.getMessage(), Instant.now(clock)));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorDto> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest()
                .body(new ErrorDto("INPUT_INVALID", "请求体无法解析: " + ex.getMostSpecificCause().getMessage(),
                        Instant.now(clock)));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDto> handleOther(Exception ex) {
        log.error("未预期的服务异常", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorDto("INTERNAL_ERROR", ex.getMessage(), Instant.now(clock)));
    }
}
