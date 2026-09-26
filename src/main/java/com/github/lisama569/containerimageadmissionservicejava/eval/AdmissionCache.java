package com.github.lisama569.containerimageadmissionservicejava.eval;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;

/**
 * 准入结论缓存。键由策略快照版本 + 归一化镜像摘要 + 证据指纹构成，
 * 因此策略或证据任一变化都会得到不同的键；策略变更时由
 * {@link com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore}
 * 主动整体失效。仅保存不可变结论。
 */
@Component
public class AdmissionCache {

    private final ConcurrentHashMap<String, AdmissionResult> store = new ConcurrentHashMap<>();

    public Optional<AdmissionResult> get(String key) {
        return Optional.ofNullable(store.get(key));
    }

    public void put(String key, AdmissionResult result) {
        store.putIfAbsent(key, result);
    }

    /** 策略变更后调用：旧快照结论一律不得继续生效。 */
    public void invalidateAll() {
        store.clear();
    }

    public int size() {
        return store.size();
    }
}
