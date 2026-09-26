package com.github.lisama569.containerimageadmissionservicejava.web.dto;

import java.time.Instant;

public record ErrorDto(String error, String message, Instant at) {
}
