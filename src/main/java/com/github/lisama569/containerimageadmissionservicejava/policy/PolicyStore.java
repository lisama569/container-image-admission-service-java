package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.exception.InvalidCandidatePolicyException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略存储：支持并发更新、一致快照读取、候选暂存、原子发布与整体回滚。
 *
 * <p>快照为不可变对象，{@link #snapshot()} 通过 {@link AtomicReference} 无锁读取；
 * 发布/回滚在同一把锁上整体替换引用，正在进行中的并发评估要么整体使用发布前快照，
 * 要么整体使用发布后快照，不会混用。版本号始终单调递增，因此发布/回滚后
 * 基于旧版本算出的缓存结论不可能再被命中。
 */
@Component
public class PolicyStore {

    private final AtomicReference<PolicySnapshot> current;
    /** 已暂存、尚未发布的候选策略（不分配线上版本号）。 */
    private final AtomicReference<List<Policy>> staged = new AtomicReference<>();
    /** 发布前的上一个快照，供整体回滚使用。 */
    private final AtomicReference<PolicySnapshot> previous = new AtomicReference<>();
    private final AtomicLong stageSeq = new AtomicLong();
    /** 发布/回滚的整体切换锁（读路径 snapshot() 不加锁）。 */
    private final Object publishLock = new Object();

    public PolicyStore() {
        // 默认策略：所有镜像需要签名与漏洞扫描证据
        Policy defaultPolicy = new Policy("default", 1, List.of(
                new Policy.PolicyRule("default-require-scan-and-signature", "**", 0,
                        Policy.Effect.ALLOW,
                        List.of(Evidence.EvidenceType.VULN_SCAN, Evidence.EvidenceType.SIGNATURE))));
        this.current = new AtomicReference<>(new PolicySnapshot(1, List.of(defaultPolicy)));
    }

    /** 返回当前一致快照（无锁）。 */
    public PolicySnapshot snapshot() {
        return current.get();
    }

    /**
     * 暂存候选策略：当场校验，不合法则抛 {@link InvalidCandidatePolicyException}，
     * 不影响线上快照。重复暂存会覆盖上一份候选。
     *
     * @return 候选策略标识（尚未生效，不分配线上版本号）
     */
    public String stage(List<Policy> candidate, CandidatePolicyValidator validator) {
        List<Policy> copy = List.copyOf(candidate);
        validator.validate(copy);
        staged.set(copy);
        String label = "candidate-" + stageSeq.incrementAndGet();
        return label;
    }

    /**
     * 原子发布：把暂存的候选策略整体切到线上，并保留发布前快照用于回滚。
     *
     * <p>发布前再次校验暂存内容（防御性）；切换在锁内完成，随后执行 afterSwap
     * （例如清空评估缓存），保证基于旧策略算出的结论不会再被复用。
     *
     * @return 发布后的新版本号
     */
    public long publish(CandidatePolicyValidator validator, Runnable afterSwap) {
        synchronized (publishLock) {
            List<Policy> candidate = staged.get();
            if (candidate == null) {
                throw new InvalidCandidatePolicyException(List.of("没有已暂存的候选策略，无法发布"));
            }
            validator.validate(candidate);
            PolicySnapshot before = current.get();
            PolicySnapshot after = new PolicySnapshot(before.version() + 1, candidate);
            current.set(after);
            previous.set(before);
            staged.set(null);
            afterSwap.run();
            return after.version();
        }
    }

    /**
     * 整体回滚：原子恢复上一个快照（版本号继续单调递增）。
     *
     * <p>回滚后再评估与发布前结论一致：恢复的是发布前同一份策略内容，
     * 而新版本号保证发布期间/旧版本上产生的缓存结论不会被误用。
     *
     * @return 回滚后的新版本号
     */
    public long rollback(Runnable afterSwap) {
        synchronized (publishLock) {
            PolicySnapshot before = current.get();
            PolicySnapshot target = previous.get();
            if (target == null) {
                throw new IllegalStateException("没有可回滚的上一个策略快照");
            }
            PolicySnapshot restored = new PolicySnapshot(before.version() + 1, target.policies());
            current.set(restored);
            // 允许“回滚的回滚”：回滚前的快照成为新的回滚目标
            previous.set(before);
            staged.set(null);
            afterSwap.run();
            return restored.version();
        }
    }

    /** 查看当前暂存的候选策略；无暂存时返回 null。 */
    public List<Policy> staged() {
        return staged.get();
    }

    /**
     * 原子替换全部策略，版本号递增；旧快照保留用于回滚。
     *
     * @return 新快照版本号
     */
    public long update(List<Policy> policies) {
        if (policies == null || policies.isEmpty()) {
            throw new IllegalArgumentException("policies must not be empty");
        }
        synchronized (publishLock) {
            PolicySnapshot before = current.get();
            PolicySnapshot next = new PolicySnapshot(before.version() + 1, List.copyOf(policies));
            current.set(next);
            previous.set(before);
            return next.version();
        }
    }
}
