package com.github.lisama569.containerimageadmissionservicejava.exception;

import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 临时例外存储。
 *
 * <p>例外语义：在 {@code [创建时刻, expiresAt)} 内有效，可被显式撤销。
 * 到期、撤销或创建时即无效（如到期时间已过）的例外<strong>不残留任何效果</strong>，
 * 判定自动回到正常策略评估结果。
 *
 * <p>线程安全：{@link ConcurrentHashMap} 保存，{@code version} 单调递增，
 * 供评估缓存做失效依据（新增/撤销例外后，旧结论不再命中）。
 */
@Component
public class TemporaryExceptionStore {

    private static final Logger log = LoggerFactory.getLogger(TemporaryExceptionStore.class);

    private static final Comparator<TemporaryException> ORDER = Comparator
            .comparingInt(TemporaryException::priority).reversed()
            .thenComparing(TemporaryException::id);

    /** 存储项：例外本体 + 撤销标记（不可变）。 */
    public record StoredException(TemporaryException exception, boolean revoked) {
    }

    private final ConcurrentMap<String, StoredException> exceptions = new ConcurrentHashMap<>();
    private final AtomicLong version = new AtomicLong(0);
    private volatile Clock clock = Clock.systemUTC();

    /** 测试用：注入固定时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * 创建一条临时例外（当场校验，非法输入直接拒绝而不是悄悄入库）。
     *
     * @throws IllegalArgumentException id/作用域/效果为空、到期时间不晚于当前时间或 ID 已存在
     */
    public TemporaryException create(TemporaryException exception) {
        if (exception == null) {
            throw new IllegalArgumentException("例外不能为空");
        }
        if (exception.id() == null || exception.id().isBlank()) {
            throw new IllegalArgumentException("例外缺少 id");
        }
        if (exception.scopePattern() == null || exception.scopePattern().isBlank()) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 缺少 scopePattern");
        }
        if (exception.effect() == null) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 缺少 effect（ALLOW/DENY）");
        }
        Instant now = clock.instant();
        if (exception.expiresAt() == null || !now.isBefore(exception.expiresAt())) {
            throw new IllegalArgumentException(
                    "例外[" + exception.id() + "] 的到期时间必须晚于当前时间 " + now);
        }
        StoredException stored = new StoredException(exception, false);
        if (exceptions.putIfAbsent(exception.id(), stored) != null) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 已存在");
        }
        version.incrementAndGet();
        log.info("exception create id={} scope={} effect={} priority={} expiresAt={}",
                exception.id(), exception.scopePattern(), exception.effect(),
                exception.priority(), exception.expiresAt());
        return exception;
    }

    /**
     * 撤销例外。
     *
     * @return true 表示本次实际撤销；不存在或已撤销返回 false。撤销立即生效且不可逆。
     */
    public boolean revoke(String id) {
        if (id == null || id.isBlank()) {
            return false;
        }
        boolean[] changed = {false};
        exceptions.computeIfPresent(id, (key, existing) -> {
            if (!existing.revoked()) {
                changed[0] = true;
                log.info("exception revoke id={}", id);
                return new StoredException(existing.exception(), true);
            }
            return existing;
        });
        if (changed[0]) {
            version.incrementAndGet();
        }
        return changed[0];
    }

    /** 全部例外（含已撤销/已过期，便于审计排查）。 */
    public List<StoredException> entries() {
        return exceptions.values().stream()
                .sorted(Comparator.comparing(e -> e.exception().id()))
                .toList();
    }

    /**
     * 返回指定时刻仍然有效（未撤销且未到期）的例外，按确定性顺序
     * （优先级降序，其次 id 字典序升序）排列。过期例外不会出现，绝不残留效果。
     */
    public List<TemporaryException> activeAt(Instant now) {
        return exceptions.values().stream()
                .filter(e -> !e.revoked())
                .map(StoredException::exception)
                .filter(e -> now.isBefore(e.expiresAt()))
                .sorted(ORDER)
                .toList();
    }

    /** 最早到期的有效例外时间；没有返回 null。用于缓存条目提前失效。 */
    public Instant earliestExpiry(Instant now) {
        return exceptions.values().stream()
                .filter(e -> !e.revoked())
                .map(StoredException::exception)
                .map(TemporaryException::expiresAt)
                .filter(expiry -> now.isBefore(expiry))
                .min(Instant::compareTo)
                .orElse(null);
    }

    /** 存储版本：新增/撤销后递增，作为评估缓存键的一部分。 */
    public long version() {
        return version.get();
    }

    /** 便捷构造（供 REST/测试使用）。 */
    public static TemporaryException exception(String id, String scopePattern, Policy.Effect effect,
                                               int priority, String reason, Instant expiresAt) {
        return new TemporaryException(id, scopePattern, effect, priority, reason, expiresAt);
    }
}
