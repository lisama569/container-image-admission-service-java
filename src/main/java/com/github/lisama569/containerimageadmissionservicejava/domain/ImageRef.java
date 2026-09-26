package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.regex.Pattern;

/**
 * 容器镜像标识：registry/repository:tag@digest。
 *
 * <p>解析规则：
 * <ul>
 *   <li>digest 以 {@code @} 分隔，必须是 {@code algo:hex} 形式；</li>
 *   <li>tag 以名称部分最后一个 {@code :} 分隔（需避开 registry 端口）；</li>
 *   <li>首段含 {@code .} 或 {@code :} 或为 {@code localhost} 时视为 registry。</li>
 * </ul>
 */
public record ImageRef(String registry, String repository, String tag, String digest) {

    private static final Pattern DIGEST_PATTERN = Pattern.compile("^[a-z0-9]+:[0-9a-fA-F]{32,}$");
    private static final Pattern TAG_PATTERN = Pattern.compile("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$");
    private static final Pattern REPO_PATTERN = Pattern.compile("^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$");

    public static ImageRef parse(String ref) {
        if (ref == null || ref.isBlank()) {
            throw new IllegalArgumentException("image ref is blank");
        }
        String digest = null;
        String namePart = ref;
        int at = ref.indexOf('@');
        if (at >= 0) {
            digest = ref.substring(at + 1);
            namePart = ref.substring(0, at);
            if (!DIGEST_PATTERN.matcher(digest).matches()) {
                throw new IllegalArgumentException("invalid digest: " + digest);
            }
        }
        String registry = null;
        String remainder = namePart;
        int slash = namePart.indexOf('/');
        if (slash > 0) {
            String first = namePart.substring(0, slash);
            if (first.contains(".") || first.contains(":") || first.equals("localhost")) {
                registry = first;
                remainder = namePart.substring(slash + 1);
            }
        }
        String tag = null;
        String repository = remainder;
        int colon = remainder.lastIndexOf(':');
        if (colon > 0) {
            tag = remainder.substring(colon + 1);
            repository = remainder.substring(0, colon);
            if (!TAG_PATTERN.matcher(tag).matches()) {
                throw new IllegalArgumentException("invalid tag: " + tag);
            }
        }
        if (!REPO_PATTERN.matcher(repository).matches()) {
            throw new IllegalArgumentException("invalid repository: " + repository);
        }
        return new ImageRef(registry, repository, tag, digest);
    }

    /** 规范化表示：registry/repository:tag@digest（缺省部分省略）。 */
    public String canonical() {
        StringBuilder sb = new StringBuilder();
        if (registry != null) {
            sb.append(registry).append('/');
        }
        sb.append(repository);
        if (tag != null) {
            sb.append(':').append(tag);
        }
        if (digest != null) {
            sb.append('@').append(digest);
        }
        return sb.toString();
    }

    /** 用于策略作用域匹配的仓库全名（含 registry）。 */
    public String scopedName() {
        return (registry != null ? registry + "/" : "") + repository;
    }
}
