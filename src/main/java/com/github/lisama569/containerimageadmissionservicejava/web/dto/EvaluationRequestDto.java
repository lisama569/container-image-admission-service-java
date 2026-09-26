package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.util.List;

public record EvaluationRequestDto(
        String requestId,
        String image,
        String tag,
        String digest,
        ManifestDto manifest,
        List<EvidenceDto> evidences
) {
}
