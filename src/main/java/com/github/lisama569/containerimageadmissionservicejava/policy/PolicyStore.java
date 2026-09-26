package com.github.lisama569.containerimageadmissionservicejava.policy;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.common.ApiException;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.eval.AdmissionCache;

/**
 * 策略存储：以 copy-on-write 方式维护唯一的当前 {@link PolicySnapshot}。
 *
 * <p>并发写入通过 {@code synchronized} 串行化；读取方拿到的快照不可变，
 * 一次评估自始至终基于同一个快照。任何成功的写入/删除都会：
 * <ol>
 *   <li>使快照版本号 +1（单调递增）；</li>
 *   <li>清空全部准入缓存，保证旧策略下的结论不再被复用。</li>
 * </ol>
 * 同名策略只允许写入更高版本，回退/重复旧版本一律拒绝（POLICY_INVALID）。
 */
@Component
public class PolicyStore {

    private record State(long version, Map<String, PolicyDefinition> policies) {
    }

    private final AtomicReference<State> state =
            new AtomicReference<>(new State(0, Map.of()));
    private final Clock clock;
    private final AdmissionCache cache;

    public PolicyStore(Clock clock, AdmissionCache cache) {
        this.clock = clock;
        this.cache = cache;
    }

    public synchronized PolicySnapshot put(String name, PolicyDefinition policy) {
        State current = state.get();
        PolicyDefinition existing = current.policies().get(name);
        if (existing != null && policy.version() <= existing.version()) {
            throw new ApiException("POLICY_INVALID: 策略 " + name + " 新版本 " + policy.version()
                    + " 必须大于当前版本 " + existing.version());
        }
        Map<String, PolicyDefinition> next = new LinkedHashMap<>(current.policies());
        next.put(name, policy);
        return commit(current, next);
    }

    public synchronized boolean delete(String name) {
        State current = state.get();
        if (!current.policies().containsKey(name)) {
            return false;
        }
        Map<String, PolicyDefinition> next = new LinkedHashMap<>(current.policies());
        next.remove(name);
        commit(current, next);
        return true;
    }

    private PolicySnapshot commit(State current, Map<String, PolicyDefinition> next) {
        PolicySnapshot snapshot =
                new PolicySnapshot(current.version() + 1, Instant.now(clock), List.copyOf(next.values()));
        state.set(new State(snapshot.snapshotVersion(), Map.copyOf(next)));
        cache.invalidateAll();
        return snapshot;
    }

    public Optional<PolicyDefinition> get(String name) {
        return Optional.ofNullable(state.get().policies().get(name));
    }

    public List<PolicyDefinition> list() {
        return new ArrayList<>(state.get().policies().values());
    }

    /** 获取当前不可变的一致策略快照。 */
    public PolicySnapshot snapshot() {
        State s = state.get();
        return new PolicySnapshot(s.version(), Instant.now(clock), List.copyOf(s.policies().values()));
    }
}
