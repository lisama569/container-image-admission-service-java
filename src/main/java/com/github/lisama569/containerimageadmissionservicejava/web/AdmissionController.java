package com.github.lisama569.containerimageadmissionservicejava.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.lisama569.containerimageadmissionservicejava.domain.AdmissionResult;
import com.github.lisama569.containerimageadmissionservicejava.domain.EvaluationInput;
import com.github.lisama569.containerimageadmissionservicejava.service.AdmissionService;
import com.github.lisama569.containerimageadmissionservicejava.service.DtoMapper;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.EvaluationRequestDto;
import com.github.lisama569.containerimageadmissionservicejava.web.dto.EvaluationResponseDto;

@RestController
@RequestMapping("/api/admission")
public class AdmissionController {

    private final AdmissionService admissionService;
    private final DtoMapper mapper;

    public AdmissionController(AdmissionService admissionService, DtoMapper mapper) {
        this.admissionService = admissionService;
        this.mapper = mapper;
    }

    @PostMapping("/evaluate")
    public EvaluationResponseDto evaluate(@RequestBody EvaluationRequestDto request) {
        EvaluationInput input = mapper.toInput(request);
        String requestId = request.requestId();
        AdmissionResult result = admissionService.evaluate(input, requestId);
        return mapper.toResponse(requestId, result);
    }
}
