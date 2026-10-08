package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.time.Instant;

/**
 * 临时例外：在有效期内对命中作用域的镜像按例外放行。
 *
 * @param id        例外 ID（非空、唯一）
 * @param scopePattern 作用域 glob（与策略规则同一套匹配语义）
 * @param effect    例外效果（ALLOW）
 * @param expiresAt 到期时间（必须晚于创建时刻）；到期后自动失效，不残留
 * @param createdAt 创建时间
 * @param reason    人工备注的例外理由
 */
public record TemporaryException(
        String id,
        String scopePattern,
        Policy.Effect effect,
        Instant expiresAt,
        Instant createdAt,
        String reason) {
}
