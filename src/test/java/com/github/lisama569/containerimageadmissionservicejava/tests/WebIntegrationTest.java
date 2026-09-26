package com.github.lisama569.containerimageadmissionservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "admission.seed-defaults=false")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class WebIntegrationTest {

    private static final String DIGEST = "sha256:" + "a".repeat(64);
    private static final String LAYER = "sha256:" + "b".repeat(64);

    @Autowired
    private MockMvc mockMvc;
    private final ObjectMapper om = new ObjectMapper();

    private Map<String, Object> strictPolicy(int version, List<String> signers) {
        return Map.of(
                "version", version,
                "enabled", true,
                "priority", 100,
                "scope", Map.of("registryPattern", "*", "repositoryPattern", "*", "tagPattern", "*"),
                "rules", List.of(Map.of(
                        "id", "r1",
                        "priority", 100,
                        "effect", "ALLOW",
                        "constraints", Map.of(
                                "requireSbom", true,
                                "requireVulnScan", true,
                                "maxSeverity", "HIGH",
                                "requireSignature", true,
                                "trustedSigners", signers,
                                "requiredAttestations", List.of("slsa/provenance"),
                                "maxEvidenceAgeSeconds", 2592000))));
    }

    private Map<String, Object> evalRequest(String requestId, String digest, Object evidences) {
        java.util.HashMap<String, Object> m = new java.util.HashMap<>();
        m.put("requestId", requestId);
        m.put("image", "registry.example.com/prod/app:v1");
        if (digest != null) {
            m.put("digest", digest);
            m.put("manifest", Map.of("digest", digest,
                    "entries", List.of(Map.of("name", "layer.tar", "digest", LAYER, "size", 123))));
        }
        m.put("evidences", evidences);
        return m;
    }

    private List<Map<String, Object>> fullEvidence() {
        return List.of(
                Map.of("id", "sbom-1", "type", "SBOM", "boundDigest", DIGEST,
                        "createdAt", "2026-09-25T00:00:00Z", "expiresAt", "2026-10-26T00:00:00Z",
                        "formatVersion", 1, "packages", List.of("libfoo-1.0")),
                Map.of("id", "scan-1", "type", "VULN_SCAN", "boundDigest", DIGEST,
                        "createdAt", "2026-09-25T00:00:00Z", "expiresAt", "2026-10-26T00:00:00Z",
                        "formatVersion", 1, "vulnerabilityCounts", Map.of("LOW", 2)),
                Map.of("id", "sig-1", "type", "SIGNATURE", "boundDigest", DIGEST,
                        "createdAt", "2026-09-25T00:00:00Z", "expiresAt", "2026-10-26T00:00:00Z",
                        "formatVersion", 1, "signer", "ci-bot"),
                Map.of("id", "att-1", "type", "ATTESTATION", "boundDigest", DIGEST,
                        "createdAt", "2026-09-25T00:00:00Z", "expiresAt", "2026-10-26T00:00:00Z",
                        "formatVersion", 1, "attestationTypes", List.of("slsa/provenance")));
    }

    private void putPolicy(int version, List<String> signers) throws Exception {
        mockMvc.perform(put("/api/policies/strict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(strictPolicy(version, signers))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("strict"))
                .andExpect(jsonPath("$.version").value(version));
    }

    @Test
    void policyPutThenAllowThenIdempotentRepeatAndAudit() throws Exception {
        putPolicy(1, List.of("ci-bot"));
        String body = om.writeValueAsString(evalRequest("web-1", DIGEST, fullEvidence()));
        mockMvc.perform(post("/api/admission/evaluate").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.reason").isEmpty())
                .andExpect(jsonPath("$.policySnapshotVersion").value(1));

        // 重复 requestId → 同一结论
        mockMvc.perform(post("/api/admission/evaluate").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"));

        mockMvc.perform(get("/api/audit/web-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("web-1"))
                .andExpect(jsonPath("$.result.decision").value("ALLOW"))
                .andExpect(jsonPath("$.result.evidenceIds").isArray());
    }

    @Test
    void tagDriftWhenDigestMissing() throws Exception {
        putPolicy(1, List.of("ci-bot"));
        Map<String, Object> req = evalRequest("web-2", null, List.of());
        req = new java.util.HashMap<>(req);
        req.remove("digest");
        mockMvc.perform(post("/api/admission/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reason").value("TAG_DRIFT"));
    }

    @Test
    void digestMismatchDistinctReason() throws Exception {
        putPolicy(1, List.of("ci-bot"));
        String other = "sha256:" + "c".repeat(64);
        Map<String, Object> req = evalRequest("web-3", DIGEST,
                List.of(Map.of("id", "sbom-x", "type", "SBOM", "boundDigest", other,
                        "createdAt", "2026-09-25T00:00:00Z", "formatVersion", 1,
                        "packages", List.of("x"))));
        mockMvc.perform(post("/api/admission/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("EVIDENCE_DIGEST_MISMATCH"));
    }

    @Test
    void invalidPolicyRejectedWith400() throws Exception {
        Map<String, Object> bad = Map.of("version", 0, "rules", List.of());
        mockMvc.perform(put("/api/policies/bad")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(bad)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("POLICY_INVALID"));
    }

    @Test
    void missingPolicyDenies() throws Exception {
        String body = om.writeValueAsString(evalRequest("web-4", DIGEST, fullEvidence()));
        mockMvc.perform(post("/api/admission/evaluate").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("POLICY_NOT_FOUND"));
    }

    @Test
    void concurrentEvaluationsAndPolicyUpdatesStayConsistent() throws Exception {
        putPolicy(1, List.of("ci-bot"));
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();
        AtomicInteger allows = new AtomicInteger();
        AtomicInteger denies = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    if (idx % 4 == 0) {
                        // 每隔几线程做一次策略更新（签名者轮换）
                        putPolicy(2, idx % 8 == 0 ? List.of("other-team") : List.of("ci-bot"));
                    } else {
                        String body = om.writeValueAsString(
                                evalRequest("cc-" + idx, DIGEST, fullEvidence()));
                        String resp = mockMvc.perform(post("/api/admission/evaluate")
                                        .contentType(MediaType.APPLICATION_JSON).content(body))
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString();
                        if (resp.contains("\"decision\":\"ALLOW\"")) {
                            allows.incrementAndGet();
                        } else {
                            denies.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
        assertThat(errors.get()).isZero();
        assertThat(allows.get() + denies.get()).isGreaterThan(0);

        // 最终策略稳定后，结论完全由最终快照决定且可重复
        String body = om.writeValueAsString(evalRequest("cc-final", DIGEST, fullEvidence()));
        String r1 = mockMvc.perform(post("/api/admission/evaluate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn().getResponse().getContentAsString();
        String r2 = mockMvc.perform(post("/api/admission/evaluate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn().getResponse().getContentAsString();
        assertThat(r1).isEqualTo(r2);
    }
}
