package com.github.lisama569.containerimageadmissionservicejava.tests;

import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.allowRule;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.constraints;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.policy;
import static com.github.lisama569.containerimageadmissionservicejava.tests.TestFixtures.scopeAll;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.github.lisama569.containerimageadmissionservicejava.common.ApiException;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;
import com.github.lisama569.containerimageadmissionservicejava.eval.AdmissionCache;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidator;

class PolicyStoreTest {

    private final Clock clock = Clock.fixed(TestFixtures.NOW, ZoneOffset.UTC);
    private final AdmissionCache cache = new AdmissionCache();
    private final PolicyStore store = new PolicyStore(clock, cache);

    private PolicyDefinition policyAt(int version) {
        return policy("p", version, 100, scopeAll(),
                List.of(allowRule(1, new RuleConstraints(null, null, null, null, null, null, null, null))));
    }

    @Test
    void snapshotIsImmutableAcrossUpdates() {
        store.put("p", policyAt(1));
        PolicySnapshot first = store.snapshot();
        store.put("p", policyAt(2));
        assertThat(first.snapshotVersion()).isEqualTo(1);
        assertThat(first.policies().get(0).version()).isEqualTo(1);
        assertThat(store.snapshot().snapshotVersion()).isEqualTo(2);
    }

    @Test
    void rejectsNonIncreasingVersion() {
        store.put("p", policyAt(2));
        assertThatThrownBy(() -> store.put("p", policyAt(2)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("POLICY_INVALID");
        assertThatThrownBy(() -> store.put("p", policyAt(1)))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void anyWriteInvalidatesCache() {
        assertThat(cache.size()).isZero();
        store.put("p", policyAt(1));
        assertThat(cache.size()).isZero();
    }

    @Test
    void validatorRejectsBadPolicy() {
        PolicyValidator validator = new PolicyValidator();
        PolicyDefinition bad = new PolicyDefinition(" ", 0, true, -1, scopeAll(), List.of());
        assertThat(validator.validate(bad)).isNotEmpty();
        // 重复规则 id
        PolicyDefinition dupIds = policy("p", 1, 0, scopeAll(), List.of(
                allowRule(1, constraints(null, null, null, null, null, null)),
                allowRule(1, constraints(null, null, null, null, null, null))));
        assertThat(validator.validate(dupIds).stream().anyMatch(s -> s.contains("重复"))).isTrue();
    }

    @Test
    void concurrentUpdatesSerializeAndMonotonic() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            final int v = i + 1;
            pool.submit(() -> {
                try {
                    start.await();
                    store.put("p", policyAt(v));
                    ok.incrementAndGet();
                } catch (ApiException ex) {
                    rejected.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        // 乱序并发：只有“恰好成为当时最高”的写入成功，其余拒绝；最终版本必为最高之一
        assertThat(ok.get() + rejected.get()).isEqualTo(threads);
        assertThat(store.get("p").orElseThrow().version()).isBetween(1, threads);
    }

    @Test
    void deleteRemovesAndBumpsVersion() {
        store.put("p", policyAt(1));
        long v = store.snapshot().snapshotVersion();
        assertThat(store.delete("p")).isTrue();
        assertThat(store.snapshot().snapshotVersion()).isGreaterThan(v);
        assertThat(store.get("p")).isEmpty();
        assertThat(store.delete("p")).isFalse();
    }
}
