package com.github.lisama569.containerimageadmissionservicejava.web.dto;

public record PolicyScopeDto(String registryPattern, String repositoryPattern, String tagPattern) {
}
