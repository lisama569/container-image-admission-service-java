package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

/**
 * 预演报告：候选策略对一批镜像的“假设性”评估结果。
 * 预演不影响线上判定，也不产生正式审计记录。
 *
 * @param candidateVersion 候选策略草稿版本号（尚未生效）
 * @param currentVersion   当前线上策略版本号
 * @param items            逐镜像对比结果
 */
public record PreviewReport(long candidateVersion, long currentVersion, List<PreviewItem> items) {
}
