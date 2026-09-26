package com.github.lisama569.containerimageadmissionservicejava.web;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.lisama569.containerimageadmissionservicejava.domain.PolicyDefinition;
import com.github.lisama569.containerimageadmissionservicejava.policy.PolicySnapshot;
import com.github.lisama569.containerimageadmissionservicejava.service.DtoMapper;
import com.github.lisama569.containerimageadmissionservicejava.service.PolicyAdminService;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.PolicyDefinitionDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.PolicyResponseDto;

@RestController
@RequestMapping("/api/policies")
public class PolicyAdminController {

    private final PolicyAdminService adminService;
    private final DtoMapper mapper;

    public PolicyAdminController(PolicyAdminService adminService, DtoMapper mapper) {
        this.adminService = adminService;
        this.mapper = mapper;
    }

    @PutMapping("/{name}")
    public PolicyResponseDto put(@PathVariable String name, @RequestBody PolicyDefinitionDto dto) {
        PolicyDefinition policy = mapper.toPolicy(name, dto);
        PolicySnapshot snapshot = adminService.put(name, policy);
        return new PolicyResponseDto(name, policy.version(), snapshot.snapshotVersion());
    }

    @GetMapping
    public List<PolicyDefinition> list() {
        return adminService.list();
    }

    @GetMapping("/{name}")
    public PolicyDefinition get(@PathVariable String name) {
        return adminService.get(name);
    }

    @DeleteMapping("/{name}")
    public PolicyResponseDto delete(@PathVariable String name) {
        PolicySnapshot snapshot = adminService.delete(name);
        return new PolicyResponseDto(name, 0, snapshot.snapshotVersion());
    }
}
