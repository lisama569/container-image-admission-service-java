package com.github.lisama569.containerimageadmissionservicejava.domain;

import java.util.List;

public record EvaluationInput(ImageRef image, ImageManifest manifest, List<Evidence> evidences) {
}
