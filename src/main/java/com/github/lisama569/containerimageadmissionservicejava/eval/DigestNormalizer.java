package com.github.lisama569.containerimageadmissionservicejava.eval;

import java.util.Locale;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * 容器镜像摘要归一化与兼容解析。
 *
 * <p>标准格式为 {@code algorithm:hex}（如 {@code sha256:abc...}）。归一化规则：
 * <ul>
 *   <li>去除首尾空白并转小写；</li>
 *   <li>仅含十六进制串时按 {@code sha256} 算法补全（兼容旧格式摘要）；</li>
 *   <li>算法段非法或十六进制长度与算法不匹配时抛出 {@link IllegalArgumentException}。</li>
 * </ul>
 */
@Component
public class DigestNormalizer {

    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern HEX96 = Pattern.compile("[0-9a-f]{96}");
    private static final Pattern ALGO = Pattern.compile("[a-z0-9]+(?:\\.[a-z0-9]+)*");

    public String normalize(String digest) {
        if (digest == null || digest.isBlank()) {
            throw new IllegalArgumentException("digest 不能为空");
        }
        String d = digest.trim().toLowerCase(Locale.ROOT);
        int idx = d.indexOf(':');
        if (idx < 0) {
            if (HEX64.matcher(d).matches()) {
                return "sha256:" + d;
            }
            throw new IllegalArgumentException("无法解析的摘要格式: " + digest);
        }
        String algo = d.substring(0, idx);
        String hex = d.substring(idx + 1);
        if (!ALGO.matcher(algo).matches()) {
            throw new IllegalArgumentException("摘要算法非法: " + algo);
        }
        boolean lenOk = switch (algo) {
            case "sha256" -> HEX64.matcher(hex).matches();
            case "sha384" -> HEX96.matcher(hex).matches();
            default -> !hex.isBlank() && hex.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        };
        if (!lenOk) {
            throw new IllegalArgumentException("摘要编码长度与算法不匹配: " + digest);
        }
        return d;
    }

    /** 两个摘要在归一化后是否一致。null 入参返回 false。 */
    public boolean equivalent(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        try {
            return normalize(a).equals(normalize(b));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
}
