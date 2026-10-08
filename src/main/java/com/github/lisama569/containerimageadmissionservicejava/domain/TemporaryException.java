package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.time.Instant;

/**
 * 临时例外：在 {@code [now, expiresAt)} 有效期内，对命中作用域的镜像
 * 临时覆盖正常策略判定（ALLOW 放行或 DENY 拒绝），到期或撤销后自动失效。
 *
 * @param id           例外 ID（非空）
 * @param scopePattern 作用域 glob（与策略规则同一套匹配语义，非空）
 * @param effect       例外效果（ALLOW/DENY）
 * @param priority     优先级（数值大者胜出，同值按 id 字典序）
 * @param reason       例外原因/说明
 * @param expiresAt    到期时间（必须晚于创建时刻）
 */
public record TemporaryException(String id, String scopePattern, Policy.Effect effect,
                                 int priority, String reason, Instant expiresAt) {
}
