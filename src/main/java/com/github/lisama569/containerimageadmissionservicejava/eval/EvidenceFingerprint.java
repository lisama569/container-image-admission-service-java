package com.github.lisama569.containerimageadmissionservicejava.eval;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.domain.Evidence;

/**
 * 证据集合指纹：对证据的全部绑定字段做规范化哈希。
 *
 * <p>指纹与证据列表顺序无关（按证据 id 排序），但对以下任何变化敏感：
 * 新增/删除证据、绑定摘要变化、时间戳/有效期变化、格式版本、签名者、
 * 证明类型、包清单、漏洞计数。输入与策略不变时指纹稳定，
 * 新增或失效证据会令指纹（进而缓存键）改变，使旧结论自然失效。
 */
@Component
public class EvidenceFingerprint {

    public String fingerprint(List<Evidence> evidences) {
        List<Evidence> sorted = (evidences == null ? List.<Evidence>of() : evidences).stream()
                .sorted((a, b) -> String.valueOf(a.id()).compareTo(String.valueOf(b.id())))
                .toList();
        MessageDigest md = sha256();
        md.update((byte) sorted.size());
        for (Evidence e : sorted) {
            update(md, String.valueOf(e.id()));
            update(md, String.valueOf(e.type()));
            update(md, String.valueOf(e.boundDigest()));
            update(md, String.valueOf(e.createdAt()));
            update(md, String.valueOf(e.expiresAt()));
            update(md, String.valueOf(e.formatVersion()));
            update(md, String.valueOf(e.signer()));
            update(md, e.attestationTypes() == null ? "" : String.join(",", e.attestationTypes().stream().sorted().toList()));
            update(md, e.packages() == null ? "" : String.join(",", e.packages().stream().sorted().toList()));
            Map<String, Integer> counts = new TreeMap<>();
            if (e.vulnerabilityCounts() != null) {
                e.vulnerabilityCounts().forEach((k, v) -> counts.put(k.name(), v));
            }
            update(md, counts.toString());
        }
        return "sha256:" + HexFormat.of().formatHex(md.digest());
    }

    private static void update(MessageDigest md, String s) {
        md.update(s.getBytes(StandardCharsets.UTF_8));
        md.update((byte) 0);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
