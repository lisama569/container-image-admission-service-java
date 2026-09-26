package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

/**
 * 不可变策略快照：一次评估只基于一个一致快照。
 */
public record PolicySnapshot(long version, List<Policy> policies) {
}
