package com.github.lisama569.containerimageadmissionservicejava.config;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyRule;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyScope;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleConstraints;
import com.github.lisama569.containerimageadmissionservicejava.domain.RuleEffect;
import com.github.lisama569.containerimageadmissionservicejava.domain.Severity;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;

/**
 * 本地演示用默认策略（admission.seed-defaults=true 时启用，默认开启）。
 * 生产/测试可通过配置关闭后自行写入策略。
 */
@Component
@ConditionalOnProperty(name = "admission.seed-defaults", havingValue = "true", matchIfMissing = true)
public class DefaultPolicySeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DefaultPolicySeeder.class);

    private final PolicyStore policyStore;

    public DefaultPolicySeeder(PolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    @Override
    public void run(ApplicationArguments args) {
        RuleConstraints requireAll = new RuleConstraints(
                true, true, Severity.HIGH, true, List.of("ci-bot@example.com"),
                List.of("slsa/provenance"), java.time.Duration.ofDays(30), null);
        PolicyRule strict = new PolicyRule("strict-allow", "生产准入要求", 100, RuleEffect.ALLOW, requireAll);
        PolicyDefinition production = new PolicyDefinition(
                "production-baseline", 1, true, 100,
                new PolicyScope("registry.example.com", "prod/*", "*"),
                List.of(strict));

        RuleConstraints denyCritical = new RuleConstraints(
                null, true, Severity.CRITICAL, null, null, null, null, null);
        PolicyRule criticalVeto = new PolicyRule("deny-critical", "存在严重漏洞即否决", 10,
                RuleEffect.DENY, denyCritical);
        RuleConstraints relaxed = new RuleConstraints(
                true, true, null, false, null, null, java.time.Duration.ofDays(90), null);
        PolicyRule relaxedAllow = new PolicyRule("relaxed-allow", "非生产基线", 100,
                RuleEffect.ALLOW, relaxed);
        PolicyDefinition general = new PolicyDefinition(
                "general-baseline", 1, true, 200,
                new PolicyScope("*", "*", "*"),
                List.of(criticalVeto, relaxedAllow));

        policyStore.put("production-baseline", production);
        policyStore.put("general-baseline", general);
        log.info("已写入默认演示策略: production-baseline@v1, general-baseline@v1");
    }
}
