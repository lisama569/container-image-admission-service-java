package com.github.lisama569.containerimageadmissionservicejava.exception;

import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 临时例外存储：支持带到期时间的例外、撤销与按镜像查找有效例外。
 *
 * <p>例外一旦到期、被撤销或创建时即无效，立即不再参与判定，不残留放行效果：
 * <ul>
 *   <li>创建时 {@code expiresAt} 必须晚于当前时间，否则当场拒绝（{@link IllegalArgumentException}）；</li>
 *   <li>{@link #activeExceptionFor} 每一刻都按当前时钟检查有效期，到期即查不到；</li>
 *   <li>撤销从存储中物理移除，后续评估不可能再命中。</li>
 * </ul>
 *
 * <p>作用域匹配与策略规则同一套 glob 语义（委托 {@link PolicyEngine}）。
 * 多个有效例外命中同一镜像时，取最早到期者，保证结果确定。
 */
@Component
public class ExceptionStore {

    private final ConcurrentHashMap<String, TemporaryException> exceptions = new ConcurrentHashMap<>();
    private final Set<String> revoked = ConcurrentHashMap.newKeySet();
    private final AtomicLong storeVersion = new AtomicLong();
    private final PolicyEngine policyEngine;
    private volatile Clock clock = Clock.systemUTC();

    public ExceptionStore(PolicyEngine policyEngine) {
        this.policyEngine = policyEngine;
    }

    /** 测试用：注入固定时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * 新增例外。非法情况（id/作用域/效果缺失、已到期、id 重复）
     * 抛 {@link IllegalArgumentException}，绝不静默放过。
     */
    public TemporaryException add(TemporaryException exception) {
        if (exception == null) {
            throw new IllegalArgumentException("exception 为 null");
        }
        if (exception.id() == null || exception.id().isBlank()) {
            throw new IllegalArgumentException("例外缺少 id");
        }
        if (exception.scopePattern() == null || exception.scopePattern().isBlank()) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 缺少 scopePattern");
        }
        if (exception.effect() == null) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 缺少 effect");
        }
        if (exception.expiresAt() == null) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 缺少 expiresAt（限时例外必须带到期时间）");
        }
        Instant now = clock.instant();
        if (!now.isBefore(exception.expiresAt())) {
            throw new IllegalArgumentException("例外[" + exception.id() + "] 已过期或立即到期: " + exception.expiresAt());
        }
        TemporaryException normalized = new TemporaryException(exception.id(), exception.scopePattern(),
                exception.effect(), exception.expiresAt(),
                exception.createdAt() != null ? exception.createdAt() : now,
                exception.reason());
        if (exceptions.putIfAbsent(exception.id(), normalized) != null) {
            throw new IllegalArgumentException("例外 id 已存在: " + exception.id());
        }
        storeVersion.incrementAndGet();
        return normalized;
    }

    /** 撤销例外：物理移除。返回是否实际撤销；不存在/已撤销/已到期返回 false。 */
    public boolean revoke(String id) {
        if (id == null || id.isBlank()) {
            return false;
        }
        TemporaryException removed = exceptions.remove(id);
        if (removed == null) {
            return false;
        }
        revoked.add(id);
        storeVersion.incrementAndGet();
        return true;
    }

    /**
     * 查找当前时刻对镜像生效的例外（未撤销、未到期、作用域命中）。
     * 多个命中时取最早到期者，其次 id 字典序，保证确定。无则 empty。
     */
    public Optional<TemporaryException> activeExceptionFor(ImageRef image) {
        Instant now = clock.instant();
        return exceptions.values().stream()
                .filter(e -> now.isBefore(e.expiresAt()))
                .filter(e -> policyEngine.scopeMatches(e.scopePattern(), image))
                .min((a, b) -> {
                    int byExpiry = a.expiresAt().compareTo(b.expiresAt());
                    if (byExpiry != 0) {
                        return byExpiry;
                    }
                    return a.id().compareTo(b.id());
                });
    }

    /** 当前未撤销的全部例外（含已到期，便于排查；到期者不再参与判定）。 */
    public List<TemporaryException> list() {
        return exceptions.values().stream()
                .sorted((a, b) -> a.id().compareTo(b.id()))
                .toList();
    }

    /** 每次新增/撤销后单调递增的例外集合版本，用作评估缓存键的一部分。 */
    public long version() {
        return storeVersion.get();
    }

    /** 该 id 是否曾经被撤销过（用于审计/排查）。 */
    public boolean wasRevoked(String id) {
        return revoked.contains(id);
    }
}
