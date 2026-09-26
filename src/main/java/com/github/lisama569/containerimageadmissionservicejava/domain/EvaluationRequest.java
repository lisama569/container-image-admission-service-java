package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

/**
 * 准入评估请求。
 *
 * @param requestId      幂等键：同一镜像的重复请求不得产生重复审计记录
 * @param imageRef       镜像标识（可含 tag 与 digest）
 * @param resolvedDigest 准入时刻从镜像仓库解析到的 tag 当前摘要（可为 null）；
 *                       与 imageRef 中的 digest 不一致时判定为标签漂移
 * @param evidenceList   随请求提交的证据
 */
public record EvaluationRequest(String requestId, String imageRef, String resolvedDigest,
                                List<Evidence> evidenceList) {
}
