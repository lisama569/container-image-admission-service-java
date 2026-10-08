package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 候选策略“先预演、再受控发布”编排。
 *
 * <p>生命周期：
 * <ol>
 *   <li>{@link #stage(List)}：暂存候选策略。当场做完整校验，
 *       非法候选策略抛 {@link PolicyValidationException}（与普通评估拒绝区分），
 *       暂存不影响线上；</li>
 *   <li>{@link #publish()}：把已暂存候选策略<strong>原子</strong>切换到线上。
 *       通过 {@link PolicyStore#publish(List)} 的整体引用替换，
 *       发布进行中并发过来的评估只会整体看到发布前或发布后快照，不会混用；
 *       同时留存发布前快照用于回滚；</li>
 *   <li>{@link #rollback()}：整体恢复到上一次发布前的快照（内容与版本号一致）。
 *       回滚后再评估，结论必须与发布前一致；由于 generation 递增，
 *       回滚前基于中间状态算出的缓存结论不会再被使用。</li>
 * </ol>
 *
 * <p>发布/回滚用同一把锁串行化，保证“暂存 → 发布”以及回滚留档不会交错。
 */
@Component
public class PolicyReleaseService {

    private static final Logger log = LoggerFactory.getLogger(PolicyReleaseService.class);

    private final PolicyStore policyStore;
    private final PolicyValidator validator;
    private final Object lifecycleLock = new Object();

    /** 已暂存、尚未发布的候选策略；null 表示当前没有草稿。 */
    private volatile List<Policy> staged;
    private volatile long draftVersion;
    /** 上一次发布前的快照，用于整体回滚；null 表示没有可回滚目标。 */
    private volatile PolicySnapshot lastBeforePublish;

    public PolicyReleaseService(PolicyStore policyStore, PolicyValidator validator) {
        this.policyStore = policyStore;
        this.validator = validator;
    }

    /**
     * 暂存候选策略（当场校验，不影响线上判定）。
     *
     * @return 草稿版本号（若随后发布，将成为线上新版本号）
     * @throws PolicyValidationException 候选策略存在任何问题
     */
    public long stage(List<Policy> policies) {
        validator.validate(policies);
        List<Policy> copy = List.copyOf(policies);
        synchronized (lifecycleLock) {
            this.staged = copy;
            this.draftVersion = policyStore.snapshot().version() + 1;
        }
        log.info("policy stage draftVersion={} policyCount={}", draftVersion, copy.size());
        return draftVersion;
    }

    /**
     * 原子发布已暂存的候选策略。
     *
     * @return 发布后的线上版本号
     * @throws IllegalStateException 没有已暂存候选策略
     */
    public long publish() {
        synchronized (lifecycleLock) {
            List<Policy> candidate = staged;
            if (candidate == null) {
                throw new IllegalStateException("没有已暂存的候选策略，无法发布");
            }
            PolicySnapshot before = policyStore.snapshot();
            PolicyStore.Published published = policyStore.publish(candidate);
            // 留存发布前快照用于回滚；发布完成清空草稿
            this.lastBeforePublish = published.before();
            this.staged = null;
            log.info("policy publish {} -> {} generation={}",
                    before.version(), published.after().version(), policyStore.generation());
            return published.after().version();
        }
    }

    /**
     * 整体回滚到上一次发布前快照。
     *
     * <p>回滚是幂等安全的：没有可回滚目标时抛 {@link IllegalStateException}。
     * 回滚恢复快照内容与版本号；generation 递增使中间状态的缓存结论全部失效。
     *
     * @return 回滚后的线上版本号
     */
    public long rollback() {
        synchronized (lifecycleLock) {
            PolicySnapshot target = lastBeforePublish;
            if (target == null) {
                throw new IllegalStateException("没有可回滚的发布");
            }
            long restored = policyStore.restore(target);
            this.lastBeforePublish = null;
            this.staged = null;
            log.info("policy rollback restoredVersion={} generation={}",
                    restored, policyStore.generation());
            return restored;
        }
    }

    /** 当前是否存在已暂存草稿。 */
    public boolean hasStaged() {
        return staged != null;
    }

    /** 草稿版本号（无草稿时返回 -1）。 */
    public long draftVersion() {
        return staged != null ? draftVersion : -1L;
    }
}
