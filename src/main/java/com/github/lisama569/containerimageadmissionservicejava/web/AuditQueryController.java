package com.github.lisama569.containerimageadmissionservicejava.web;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.lisama569.containerimageadmissionservicejava.audit.AuditRecord;
import com.github.lisama569.containerimageadmissionservicejava.audit.AuditService;

@RestController
@RequestMapping("/api/audit")
public class AuditQueryController {

    private final AuditService auditService;

    public AuditQueryController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/{requestId}")
    public AuditRecord byRequestId(@PathVariable String requestId) {
        return auditService.findByRequestId(requestId)
                .orElseThrow(() -> new com.github.lisama569.containerimageadmissionservicejava.common.ApiException(
                        "审计记录不存在: " + requestId));
    }

    @GetMapping
    public List<AuditRecord> list() {
        return auditService.list();
    }
}
