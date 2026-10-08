package com.github.lisama569.containerimageadmissionservicejava.domain;

/**
 * 预演单项：同一镜像在当前线上策略与候选策略下的结论对比。
 *
 * @param imageRef       镜像标识（规范化）
 * @param currentVerdict 当前线上结论（ALLOW/DENY）
 * @param currentReason  当前线上拒绝原因（ALLOW 时为 null）
 * @param candidateVerdict 候选策略下的结论
 * @param candidateReason 候选策略下的拒绝原因（ALLOW 时为 null）
 * @param changed        结论是否发生变化
 */
public record PreviewItem(String imageRef,
                          EvaluationDecision.Verdict currentVerdict,
                          DenyReason currentReason,
                          EvaluationDecision.Verdict candidateVerdict,
                          DenyReason candidateReason,
                          boolean changed) {
}
