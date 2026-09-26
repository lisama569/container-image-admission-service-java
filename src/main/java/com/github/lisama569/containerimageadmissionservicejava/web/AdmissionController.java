package com.github.lisama569.containerimageadmissionservicejava.web;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 准入评估 REST 接口。
 */
@RestController
@RequestMapping("/api/v1/admission")
public class AdmissionController {

    private final AdmissionService admissionService;
    private final PolicyStore policyStore;
    private final AuditLog auditLog;

    public AdmissionController(AdmissionService admissionService, PolicyStore policyStore,
                               AuditLog auditLog) {
        this.admissionService = admissionService;
        this.policyStore = policyStore;
        this.auditLog = auditLog;
    }

    /** 评估镜像准入。拒绝时返回 422 及可区分的拒绝原因。 */
    @PostMapping("/evaluate")
    public ResponseEntity<EvaluationDecision> evaluate(@RequestBody EvaluationRequest request) {
        EvaluationDecision decision = admissionService.evaluate(request);
        if (decision.verdict() == EvaluationDecision.Verdict.ALLOW) {
            return ResponseEntity.ok(decision);
        }
        return ResponseEntity.unprocessableEntity().body(decision);
    }

    /** 查看当前策略快照。 */
    @GetMapping("/policies")
    public PolicySnapshot policies() {
        return policyStore.snapshot();
    }

    /** 原子更新策略，返回新版本号。 */
    @PutMapping("/policies")
    public Map<String, Long> updatePolicies(@RequestBody List<Policy> policies) {
        return Map.of("version", policyStore.update(policies));
    }

    /** 查看审计记录。 */
    @GetMapping("/audit")
    public List<AuditLog.AuditEntry> audit() {
        return auditLog.entries();
    }
}
