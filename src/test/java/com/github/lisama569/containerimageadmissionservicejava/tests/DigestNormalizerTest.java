package com.github.lisama569.containerimageadmissionservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import com.github.lisama569.containerimageadmissionservicejava.eval.DigestNormalizer;

class DigestNormalizerTest {

    private static final String HEX64 = "a".repeat(64);
    private final DigestNormalizer normalizer = new DigestNormalizer();

    @Test
    void keepsStandardDigest() {
        assertThat(normalizer.normalize("sha256:" + HEX64)).isEqualTo("sha256:" + HEX64);
    }

    @Test
    void lowercasesAndTrims() {
        assertThat(normalizer.normalize("  SHA256:" + HEX64.toUpperCase() + " "))
                .isEqualTo("sha256:" + HEX64);
    }

    @Test
    void completesBareHexAsSha256() {
        assertThat(normalizer.normalize(HEX64)).isEqualTo("sha256:" + HEX64);
    }

    @Test
    void rejectsBlank() {
        assertThatThrownBy(() -> normalizer.normalize(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsWrongLength() {
        assertThatThrownBy(() -> normalizer.normalize("sha256:abc"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equivalentAcrossForms() {
        assertThat(normalizer.equivalent(HEX64, "sha256:" + HEX64)).isTrue();
        assertThat(normalizer.equivalent(HEX64, "sha256:" + "b".repeat(64))).isFalse();
        assertThat(normalizer.equivalent(null, HEX64)).isFalse();
    }
}
