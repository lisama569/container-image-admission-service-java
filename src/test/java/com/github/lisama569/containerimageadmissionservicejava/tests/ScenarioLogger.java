package com.github.lisama569.containerimageadmissionservicejava.tests;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 测试场景日志小工具：让测试日志清晰显示覆盖了哪些业务、各自有哪些用例。
 */
public final class ScenarioLogger {

    private final Logger log;

    private ScenarioLogger(Class<?> clazz) {
        this.log = LoggerFactory.getLogger(clazz);
    }

    public static ScenarioLogger of(Class<?> clazz) {
        return new ScenarioLogger(clazz);
    }

    /** 开始一个业务场景。 */
    public void scenario(String name) {
        log.info(">>> 业务场景: {}", name);
    }

    /** 记录一个具体用例及其验证点。 */
    public void casee(String caseName, String assertion) {
        log.info("    - 用例 [{}] => 断言: {}", caseName, assertion);
    }

    /** 场景汇总。 */
    public void summary(String summary) {
        log.info("<<< 场景结论: {}", summary);
    }
}
