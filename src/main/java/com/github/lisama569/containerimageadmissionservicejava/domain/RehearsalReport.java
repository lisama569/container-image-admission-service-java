package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

/**
 * 预演结果：对一批镜像按当前策略与候选策略分别评估后的对比。
 *
 * <p>预演不影响线上判定，也不产生审计记录。
 *
 * @param currentVersion 当前线上策略版本
 * @param candidateLabel 候选策略标识（尚未生效，不分配线上版本号）
 * @param changes        结论发生变化的镜像对比
 * @param unchanged      结论未变化的镜像引用
 */
public record RehearsalReport(long currentVersion, String candidateLabel,
                              List<ImageChange> changes, List<String> unchanged) {

    /**
     * 单个镜像的结论变化：从什么变成什么。
     */
    public record ImageChange(String imageRef,
                              EvaluationDecision before,
                              EvaluationDecision after) {
    }
}
