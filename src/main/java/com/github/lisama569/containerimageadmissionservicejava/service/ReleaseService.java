package com.github.lisama569.containerimageadmissionservicejava.service;

import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.policy.CandidatePolicyValidator;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

/**
 * 受控发布服务：候选策略先校验/暂存，确认后原子切到线上；支持整体回滚。
 *
 * <p>发布与回滚都是 {@link PolicyStore} 内的整体快照替换，正在进行中的并发评估
 * 要么整体用发布前策略，要么整体用发布后策略；切换成功后立即清空评估缓存，
 * 基于旧版本算出的结论不会再被命中。发布失败（如候选不合法、无暂存）时
 * 线上快照与缓存都不会被动到。
 */
@Service
public class ReleaseService {

    private static final Logger log = LoggerFactory.getLogger(ReleaseService.class);

    private final PolicyStore policyStore;
    private final CandidatePolicyValidator candidatePolicyValidator;
    private final AdmissionService admissionService;

    public ReleaseService(PolicyStore policyStore, CandidatePolicyValidator candidatePolicyValidator,
                          AdmissionService admissionService) {
        this.policyStore = policyStore;
        this.candidatePolicyValidator = candidatePolicyValidator;
        this.admissionService = admissionService;
    }

    /** 校验并暂存候选策略（不影响线上）。返回候选标识。 */
    public String stage(List<Policy> candidate) {
        Objects.requireNonNull(candidate, "candidate");
        String label = policyStore.stage(candidate, candidatePolicyValidator);
        log.info("policy staged label={} policies={}", label, candidate.size());
        return label;
    }

    /** 原子发布已暂存的候选策略。返回新版本号；无暂存/校验失败时线上不变。 */
    public long publish() {
        long version = policyStore.publish(candidatePolicyValidator, admissionService::invalidateCache);
        log.info("policy published version={} (cache invalidated)", version);
        return version;
    }

    /** 整体回滚到发布前快照（新版本号单调递增）。返回回滚后的新版本号。 */
    public long rollback() {
        long version = policyStore.rollback(admissionService::invalidateCache);
        log.info("policy rolled back version={} (cache invalidated)", version);
        return version;
    }
}
