package com.github.lisama569.containerimageadmissionservicejava.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.github.lisama569.containerimageadmissionservicejava.common.ApiException;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyValidator;

/**
 * 策略管理：写入前做字段合法性校验，非法策略以 POLICY_INVALID 拒绝，绝不静默放行。
 */
@Service
public class PolicyAdminService {

    private final PolicyStore policyStore;
    private final PolicyValidator validator;

    public PolicyAdminService(PolicyStore policyStore, PolicyValidator validator) {
        this.policyStore = policyStore;
        this.validator = validator;
    }

    public PolicySnapshot put(String name, PolicyDefinition policy) {
        List<String> errors = validator.validate(policy);
        if (!errors.isEmpty()) {
            throw new ApiException("POLICY_INVALID: " + String.join("; ", errors));
        }
        return policyStore.put(name, policy);
    }

    public PolicyDefinition get(String name) {
        return policyStore.get(name)
                .orElseThrow(() -> new ApiException("POLICY_NOT_FOUND: 策略不存在: " + name));
    }

    public List<PolicyDefinition> list() {
        return policyStore.list();
    }

    public PolicySnapshot delete(String name) {
        if (!policyStore.delete(name)) {
            throw new ApiException("POLICY_NOT_FOUND: 策略不存在: " + name);
        }
        return policyStore.snapshot();
    }
}
