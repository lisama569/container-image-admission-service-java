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
 */
@Component
public class PolicyStore {

    private final AtomicReference<PolicySnapshot> current;

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
     * 原子替换全部策略，版本号递增。
     *
     * @return 新快照版本号
     */
    public long update(List<Policy> policies) {
        if (policies == null || policies.isEmpty()) {
            throw new IllegalArgumentException("policies must not be empty");
        }
        PolicySnapshot next = current.updateAndGet(prev ->
                new PolicySnapshot(prev.version() + 1, List.copyOf(policies)));
        return next.version();
    }
}
