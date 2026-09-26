package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

public record ImageManifest(String digest, List<ManifestEntry> entries) {
}
