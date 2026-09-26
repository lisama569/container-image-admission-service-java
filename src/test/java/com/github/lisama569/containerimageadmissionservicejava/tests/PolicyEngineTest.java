package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyEngine;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyEngineTest {

    private final PolicyEngine engine = new PolicyEngine();

    private ImageRef img(String ref) {
        return ImageRef.parse(ref);
    }

    @Test
    void scopeGlobMatching() {
        assertTrue(engine.scopeMatches("**", img("reg.example.com/a/b:1")));
        assertTrue(engine.scopeMatches("reg.example.com/*", img("reg.example.com/app:1")));
        assertFalse(engine.scopeMatches("reg.example.com/*", img("reg.example.com/team/app:1")));
        assertTrue(engine.scopeMatches("reg.example.com/**", img("reg.example.com/team/app:1")));
        assertTrue(engine.scopeMatches("*/app", img("reg.example.com/app:1")));
        assertFalse(engine.scopeMatches("other.example.com/**", img("reg.example.com/app:1")));
    }

    @Test
    void matchedRulesSortedDeterministically() {
        Policy p = new Policy("p", 1, List.of(
                new Policy.PolicyRule("z-low", "**", 1, Policy.Effect.ALLOW, List.of()),
                new Policy.PolicyRule("b-high", "**", 10, Policy.Effect.DENY, List.of()),
                new Policy.PolicyRule("a-high", "**", 10, Policy.Effect.ALLOW, List.of())));
        List<Policy.PolicyRule> matched = engine.matchRules(new PolicySnapshot(1, List.of(p)),
                img("reg.example.com/app:1"));
        // 优先级降序；同优先级按 ruleId 字典序
        assertEquals(List.of("a-high", "b-high", "z-low"),
                matched.stream().map(Policy.PolicyRule::ruleId).toList());
    }

    @Test
    void noMatchReturnsEmpty() {
        Policy p = new Policy("p", 1, List.of(
                new Policy.PolicyRule("r1", "prod.example.com/**", 1, Policy.Effect.ALLOW, List.of())));
        assertTrue(engine.matchRules(new PolicySnapshot(1, List.of(p)),
                img("dev.example.com/app:1")).isEmpty());
    }
}
