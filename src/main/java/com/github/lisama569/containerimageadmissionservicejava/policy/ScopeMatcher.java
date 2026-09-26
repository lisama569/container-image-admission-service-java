package com.github.lisama569.containerimageadmissionservicejava.policy;

import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyScope;

/**
 * 策略作用域解析。registry/repository/tag 三段均使用大小写不敏感的 glob
 * 表达式（{@code *} 匹配任意字符序列，{@code ?} 匹配单个字符）；
 * 字段为 null/空白时等价于 {@code *}。三段全部命中才算作用域命中。
 */
@Component
public class ScopeMatcher {

    public boolean matches(PolicyScope scope, ImageRef image) {
        if (scope == null) {
            return true;
        }
        return globMatches(scope.registryPattern(), image.registry())
                && globMatches(scope.repositoryPattern(), image.repository())
                && globMatches(scope.tagPattern(), image.tag());
    }

    private boolean globMatches(String pattern, String value) {
        String p = (pattern == null || pattern.isBlank()) ? "*" : pattern.trim();
        String v = value == null ? "" : value;
        StringBuilder sb = new StringBuilder("(?i)\\A");
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            switch (c) {
                case '*' -> sb.append(".*");
                case '?' -> sb.append('.');
                default -> sb.append(Pattern.quote(String.valueOf(c)));
            }
        }
        sb.append("\\z");
        return Pattern.compile(sb.toString()).matcher(v).matches();
    }
}
