package com.github.lisama569.containerimageadmissionservicejava.policy;

import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 策略引擎：作用域解析、优先级排序、确定性冲突处理。
 *
 * <p>作用域模式针对镜像的 {@code registry/repository} 全名匹配：
 * <ul>
 *   <li>{@code **} 匹配任意（含跨段）字符；</li>
 *   <li>{@code *} 匹配单段内任意字符；</li>
 *   <li>其余字符按字面匹配。</li>
 * </ul>
 *
 * <p>命中规则排序确定：优先级降序，其次 ruleId 字典序升序。
 * 冲突处理：取排序后的第一条规则的效果（ALLOW 或 DENY），
 * 即高优先级规则胜出；同优先级时 ruleId 字典序小者胜出，结果可重现。
 */
@Component
public class PolicyEngine {

    private static final Comparator<Policy.PolicyRule> RULE_ORDER = Comparator
            .comparingInt(Policy.PolicyRule::priority).reversed()
            .thenComparing(Policy.PolicyRule::ruleId);

    /**
     * 解析命中镜像的规则，按确定性顺序返回（优先级降序，其次 ruleId 字典序）。
     */
    public List<Policy.PolicyRule> matchRules(PolicySnapshot snapshot, ImageRef image) {
        return snapshot.policies().stream()
                .flatMap(p -> p.rules().stream())
                .filter(r -> scopeMatches(r.scopePattern(), image))
                .sorted(RULE_ORDER)
                .toList();
    }

    /**
     * 判断 scope 模式是否匹配镜像的 registry/repository 全名。
     */
    public boolean scopeMatches(String scopePattern, ImageRef image) {
        if (scopePattern == null || scopePattern.isBlank()) {
            return false;
        }
        return toRegex(scopePattern).matcher(image.scopedName()).matches();
    }

    private Pattern toRegex(String glob) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*') {
                if (i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
                    sb.append(".*");
                    i++;
                } else {
                    sb.append("[^/]*");
                }
            } else if ("\\.[]{}()+-^$?|".indexOf(c) >= 0) {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return Pattern.compile(sb.toString());
    }
}
