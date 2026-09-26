package com.github.lisama569.containerimageadmissionservicejava.domain;

public record PolicyScope(String registryPattern, String repositoryPattern, String tagPattern) {
}
