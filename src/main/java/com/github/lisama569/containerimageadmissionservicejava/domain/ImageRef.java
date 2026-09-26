package com.github.lisama569.containerimageadmissionservicejava.domain;

/**
 * 镜像标识。registry/repository/tag/digest 四元组。
 * tag 与 digest 至少需要其一；digest 是评估绑定的权威标识。
 */
public record ImageRef(String registry, String repository, String tag, String digest) {

    /** 人类可读的完整引用：registry/repository[:tag][@digest]。 */
    public String reference() {
        StringBuilder sb = new StringBuilder();
        if (registry != null && !registry.isBlank()) {
            sb.append(registry).append('/');
        }
        sb.append(repository);
        if (tag != null && !tag.isBlank()) {
            sb.append(':').append(tag);
        }
        if (digest != null && !digest.isBlank()) {
            sb.append('@').append(digest);
        }
        return sb.toString();
    }
}
