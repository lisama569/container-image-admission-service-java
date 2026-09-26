package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.util.List;

public record ManifestDto(String digest, List<ManifestEntryDto> entries) {
}
