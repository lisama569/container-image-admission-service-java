package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略存储：支持并发更新与一致快照读取。
 *
 * <p>快照为不可变对象，通过 {@link AtomicReference} 整体替换，
 * 读取方无需加锁即可拿到一致快照；版本号单调递增。
 *
 * <p>另外维护单调递增的 {@code generation}（发布、回滚都会 +1），
 * 供评估缓存做失效依据：即使回滚到旧版本，generation 也不同，
 * 保证“发布/回滚后，基于旧状态算出的结论不会再被拿来用”。
 */
@Component
public class PolicyStore {

    private record State(PolicySnapshot snapshot, long generation) {
    }

    private final AtomicReference<State> current;

    public PolicyStore() {
        // 默认策略：所有镜像需要签名与漏洞扫描证据
        Policy defaultPolicy = new Policy("default", 1, List.of(
                new Policy.PolicyRule("default-require-scan-and-signature", "**", 0,
                        Policy.Effect.ALLOW,
                        List.of(Evidence.EvidenceType.VULN_SCAN, Evidence.EvidenceType.SIGNATURE))));
        this.current = new AtomicReference<>(
                new State(new PolicySnapshot(1, List.of(defaultPolicy)), 0L));
    }

    /** 返回当前一致快照（无锁）。 */
    public PolicySnapshot snapshot() {
        return current.get().snapshot();
    }

    /** 当前代次：每次发布/回滚都单调递增，用于缓存失效。 */
    public long generation() {
        return current.get().generation();
    }

    /**
     * 原子替换全部策略，版本号递增。
     *
     * @return 新快照版本号
     */
    public long update(List<Policy> policies) {
        if (policies == null || policies.isEmpty()) {
            throw new IllegalArgumentException("policies must not be empty");
        }
        State next = current.updateAndGet(prev ->
                new State(new PolicySnapshot(prev.snapshot().version() + 1, List.copyOf(policies)),
                        prev.generation() + 1));
        return next.snapshot().version();
    }

    /**
     * 受控发布：把已校验的候选快照原子切换到线上。
     *
     * <p>整体替换 {@link AtomicReference}，因此发布进行中并发过来的评估，
     * 要么拿到发布前快照、要么拿到发布后快照，绝不会混用两个快照的规则。
     *
     * @param candidate 已校验通过的候选策略
     * @return 发布结果（含发布前后快照）
     */
    public Published publish(List<Policy> candidate) {
        if (candidate == null || candidate.isEmpty()) {
            throw new IllegalArgumentException("candidate must not be empty");
        }
        State prev = current.getAndUpdate(state -> new State(
                new PolicySnapshot(state.snapshot().version() + 1, List.copyOf(candidate)),
                state.generation() + 1));
        return new Published(prev.snapshot(), current.get().snapshot());
    }

    /**
     * 精确恢复到指定快照（整体回滚）：快照内容与版本号都恢复原样，
     * 但 generation 继续 +1，确保回滚前基于中间状态算出的缓存结论全部失效。
     *
     * @return 恢复后的线上版本号
     */
    public long restore(PolicySnapshot target) {
        if (target == null) {
            throw new IllegalArgumentException("target snapshot must not be null");
        }
        State next = current.updateAndGet(prev -> new State(target, prev.generation() + 1));
        return next.snapshot().version();
    }

    /** 一次发布的前后快照，用于失败/回滚留档。 */
    public record Published(PolicySnapshot before, PolicySnapshot after) {
    }
}
