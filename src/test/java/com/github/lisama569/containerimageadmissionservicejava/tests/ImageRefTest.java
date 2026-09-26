package com.github.lisama569.containerimageadmissionservicejava.tests;

import com.github.lisama569.containerimageadmissionservicejava.domain.ImageRef;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ImageRefTest {

    private static final String DIGEST = "sha256:" + "a".repeat(64);

    @Test
    void parsesFullRef() {
        ImageRef ref = ImageRef.parse("registry.example.com/team/app:1.0@" + DIGEST);
        assertEquals("registry.example.com", ref.registry());
        assertEquals("team/app", ref.repository());
        assertEquals("1.0", ref.tag());
        assertEquals(DIGEST, ref.digest());
        assertEquals("registry.example.com/team/app:1.0@" + DIGEST, ref.canonical());
    }

    @Test
    void parsesRefWithoutRegistry() {
        ImageRef ref = ImageRef.parse("library/nginx:latest");
        assertNull(ref.registry());
        assertEquals("library/nginx", ref.repository());
        assertEquals("latest", ref.tag());
        assertEquals("library/nginx", ref.scopedName());
    }

    @Test
    void parsesRegistryWithPort() {
        ImageRef ref = ImageRef.parse("localhost:5000/app:2.0");
        assertEquals("localhost:5000", ref.registry());
        assertEquals("app", ref.repository());
        assertEquals("2.0", ref.tag());
    }

    @Test
    void rejectsBlankAndBadDigestAndBadRepo() {
        assertThrows(IllegalArgumentException.class, () -> ImageRef.parse(""));
        assertThrows(IllegalArgumentException.class, () -> ImageRef.parse("repo:tag@sha256:xyz"));
        assertThrows(IllegalArgumentException.class, () -> ImageRef.parse("UPPER/repo:tag"));
    }
}
