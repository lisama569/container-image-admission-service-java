package com.github.lisama569.containerimageadmissionservicejava.web;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.domain.RehearsalReport;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import com.github.lisama569.containerimageadmissionservicejava.exception.ExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import com.github.lisama569.containerimageadmissionservicejava.service.RehearsalService;
import com.github.lisama569.containerimageadmissionservicejava.service.ReleaseService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 准入评估 REST 接口：评估、预演、受控发布/回滚、临时例外。
 */
@RestController
@RequestMapping("/api/v1/admission")
public class AdmissionController {

    private final AdmissionService admissionService;
    private final PolicyStore policyStore;
    private final AuditLog auditLog;
    private final RehearsalService rehearsalService;
    private final ReleaseService releaseService;
    private final ExceptionStore exceptionStore;

    public AdmissionController(AdmissionService admissionService, PolicyStore policyStore,
                               AuditLog auditLog, RehearsalService rehearsalService,
                               ReleaseService releaseService, ExceptionStore exceptionStore) {
        this.admissionService = admissionService;
        this.policyStore = policyStore;
        this.auditLog = auditLog;
        this.rehearsalService = rehearsalService;
        this.releaseService = releaseService;
        this.exceptionStore = exceptionStore;
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

    /** 预演：候选策略对一批请求“如果按这份策略判”的结论对比，不影响线上、不留判定记录。 */
    @PostMapping("/rehearse")
    public RehearsalReport rehearse(@RequestBody RehearseRequest body) {
        return rehearsalService.rehearse(body.policies(), body.requests());
    }

    /** 暂存候选策略（先校验，不生效）。 */
    @PostMapping("/policies/stage")
    public Map<String, String> stage(@RequestBody List<Policy> policies) {
        return Map.of("candidate", releaseService.stage(policies));
    }

    /** 原子发布已暂存的候选策略。 */
    @PostMapping("/policies/publish")
    public Map<String, Long> publish() {
        return Map.of("version", releaseService.publish());
    }

    /** 整体回滚到发布前快照。 */
    @PostMapping("/policies/rollback")
    public Map<String, Long> rollback() {
        return Map.of("version", releaseService.rollback());
    }

    /** 查看当前策略快照。 */
    @GetMapping("/policies")
    public PolicySnapshot policies() {
        return policyStore.snapshot();
    }

    /** 原子更新策略（保留旧快照可回滚），返回新版本号。 */
    @PutMapping("/policies")
    public Map<String, Long> updatePolicies(@RequestBody List<Policy> policies) {
        return Map.of("version", policyStore.update(policies));
    }

    /** 创建带到期时间的临时例外。 */
    @PostMapping("/exceptions")
    public TemporaryException addException(@RequestBody TemporaryException exception) {
        return exceptionStore.add(exception);
    }

    /** 撤销临时例外。 */
    @DeleteMapping("/exceptions/{id}")
    public Map<String, Boolean> revokeException(@PathVariable String id) {
        return Map.of("revoked", exceptionStore.revoke(id));
    }

    /** 查看全部未撤销例外（含已到期，到期者不再生效）。 */
    @GetMapping("/exceptions")
    public List<TemporaryException> exceptions() {
        return exceptionStore.list();
    }

    /** 查看审计记录。 */
    @GetMapping("/audit")
    public List<AuditLog.AuditEntry> audit() {
        return auditLog.entries();
    }

    /** 预演请求体：候选策略 + 待评估的一批请求。 */
    public record RehearseRequest(List<Policy> policies, List<EvaluationRequest> requests) {
    }
}
