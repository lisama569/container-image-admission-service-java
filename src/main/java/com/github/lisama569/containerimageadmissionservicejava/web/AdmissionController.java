package com.github.lisama569.containerimageadmissionservicejava.web;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditLog;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationDecision;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationRequest;
import com.github.lisama569.containerimageadmissionservicejava.domain.Policy;
import com.github.lisama569.containerimageadmissionservicejava.domain.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.domain.PreviewReport;
import com.github.lisama569.containerimageadmissionservicejava.domain.TemporaryException;
import com.github.lisama569.containerimageadmissionservicejava.exception.TemporaryExceptionStore;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyReleaseService;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicyStore;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import com.github.lisama569.containerimageadmissionservicejava.service.PolicyPreviewService;
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
 * 准入评估 REST 接口。
 */
@RestController
@RequestMapping("/api/v1/admission")
public class AdmissionController {

    private final AdmissionService admissionService;
    private final PolicyStore policyStore;
    private final AuditLog auditLog;
    private final PolicyReleaseService releaseService;
    private final PolicyPreviewService previewService;
    private final TemporaryExceptionStore exceptionStore;

    public AdmissionController(AdmissionService admissionService, PolicyStore policyStore,
                               AuditLog auditLog, PolicyReleaseService releaseService,
                               PolicyPreviewService previewService,
                               TemporaryExceptionStore exceptionStore) {
        this.admissionService = admissionService;
        this.policyStore = policyStore;
        this.auditLog = auditLog;
        this.releaseService = releaseService;
        this.previewService = previewService;
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

    /** 查看当前策略快照。 */
    @GetMapping("/policies")
    public PolicySnapshot policies() {
        return policyStore.snapshot();
    }

    /** 原子更新策略，返回新版本号（保留兼容）。 */
    @PutMapping("/policies")
    public Map<String, Long> updatePolicies(@RequestBody List<Policy> policies) {
        // 走受控发布：先校验暂存，再原子发布，保证非法策略无法直接上线
        releaseService.stage(policies);
        return Map.of("version", releaseService.publish());
    }

    /**
     * 预演：用候选策略对一批镜像做假设性评估，返回逐镜像结论变化。
     * 不影响线上判定，不产生审计记录。候选策略非法时返回 400。
     */
    @PostMapping("/policies/preview")
    public PreviewReport preview(@RequestBody PreviewRequest body) {
        return previewService.preview(body.candidatePolicies(), body.targets());
    }

    /** 暂存候选策略（当场校验，不生效），返回草稿版本号。 */
    @PostMapping("/policies/stage")
    public Map<String, Long> stage(@RequestBody List<Policy> policies) {
        return Map.of("draftVersion", releaseService.stage(policies));
    }

    /** 将已暂存候选策略原子发布到线上，返回新版本号。 */
    @PostMapping("/policies/publish")
    public Map<String, Long> publish() {
        return Map.of("version", releaseService.publish());
    }

    /** 整体回滚到上一次发布前快照，返回回滚后版本号。 */
    @PostMapping("/policies/rollback")
    public Map<String, Long> rollback() {
        return Map.of("version", releaseService.rollback());
    }

    /** 创建带到期时间的临时例外。 */
    @PostMapping("/exceptions")
    public TemporaryException createException(@RequestBody TemporaryException exception) {
        return exceptionStore.create(exception);
    }

    /** 列出全部例外（含已撤销/已过期，便于排查）。 */
    @GetMapping("/exceptions")
    public List<TemporaryExceptionStore.StoredException> exceptions() {
        return exceptionStore.entries();
    }

    /** 撤销例外（立即生效）。 */
    @DeleteMapping("/exceptions/{id}")
    public Map<String, Object> revokeException(@PathVariable String id) {
        boolean revoked = exceptionStore.revoke(id);
        return Map.of("id", id, "revoked", revoked);
    }

    /** 查看审计记录。 */
    @GetMapping("/audit")
    public List<AuditLog.AuditEntry> audit() {
        return auditLog.entries();
    }

    /** 预演请求体：候选策略 + 待预演评估目标（镜像/解析摘要/证据，与评估接口同构）。 */
    public record PreviewRequest(List<Policy> candidatePolicies,
                                 List<EvaluationRequest> targets) {
    }
}
