# §20 Execution Attestation

**Status:** Draft  
**Version:** 1.1  
**Created:** 2026-02-16  
**Authors:** APS Working Group  

## 20.1 Introduction

This section defines the `ExecutionAttestation` artifact type, which binds agent work products to verifiable execution environments. By linking a `SecurityEnvelope` (§12) to a cryptographic measurement of the runtime, verifiers can establish not only *what* an agent produced but *where* and *under what constraints* the computation occurred.

The mechanism addresses two threat classes:

1. **Environment spoofing** — an agent claims execution in a trusted environment but actually ran in an unrestricted one.
2. **Replay attacks** — a previously valid attestation is resubmitted for unrelated work.

### 20.1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

| Term | Definition |
|------|-----------|
| Executor | The runtime environment that performs agent work |
| Verifier | A party that checks an attestation report |
| Measurement | A set of cryptographic hashes describing the executor state |
| Platform | The isolation technology providing attestation capability |

## 20.2 ExecutionAttestation Artifact

An `ExecutionAttestation` is a signed JSON object with the following top-level fields:

```json
{
  "type": "ExecutionAttestation",
  "version": "1.1",
  "envelope_hash": "<SHA-256 of the SecurityEnvelope>",
  "measurement": { ... },
  "platform": { ... },
  "nonce": "<verifier-supplied nonce>",
  "timestamp": "<ISO 8601>",
  "report_signature": "<base64url-encoded signature>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | REQUIRED | MUST be `"ExecutionAttestation"` |
| `version` | string | REQUIRED | Specification version. MUST be `"1.1"` |
| `envelope_hash` | string | REQUIRED | SHA-256 hex digest of the referenced `SecurityEnvelope` |
| `measurement` | object | REQUIRED | Runtime measurement (§20.4) |
| `platform` | object | REQUIRED | Platform descriptor (§20.3) |
| `nonce` | string | REQUIRED | Verifier-supplied challenge (§20.5) |
| `timestamp` | string | REQUIRED | ISO 8601 UTC timestamp of attestation generation |
| `report_signature` | string | REQUIRED | Signature over the canonical JSON of all other fields |

The `report_signature` MUST be produced by a key whose trust anchor is appropriate to the declared `platform.type` (see §20.3). For hardware TEE platforms, this MUST be a platform-rooted key. For software platforms, this MAY be an agent-held key.

### 20.2.1 Canonical Serialization

Before signing, the attestation object (excluding `report_signature`) MUST be serialized using JCS (RFC 8785). The signature is computed over the resulting byte string.

### 20.2.2 Hash of Attestation

The `attestation_hash` used for binding (§20.7) is the SHA-256 hex digest of the complete attestation object *including* `report_signature`, serialized with JCS.

## 20.3 Supported Platforms

The `platform` object describes the isolation technology:

```json
{
  "type": "<platform-type>",
  "vendor": "<optional vendor identifier>",
  "version": "<platform version>",
  "trust_level": <0-3>
}
```

### 20.3.1 Hardware TEE Platforms (Trust Level 3)

| `platform.type` | Vendor | Description |
|-----------------|--------|-------------|
| `sgx` | Intel | Intel SGX enclaves |
| `tdx` | Intel | Intel TDX trust domains |
| `sev` | AMD | AMD SEV / SEV-SNP encrypted VMs |
| `trustzone` | ARM | ARM TrustZone secure world |
| `nitro` | AWS | AWS Nitro Enclaves |

For hardware TEE platforms, `report_signature` MUST be rooted in the platform's hardware attestation key chain. Verifiers MUST validate the signature against the vendor's published root certificates.

- **SGX/TDX:** The report MUST include the `MRENCLAVE` or `MRTD` value in `measurement.runtime_hash`.
- **SEV-SNP:** The report MUST include the launch measurement in `measurement.runtime_hash`.
- **Nitro Enclaves:** The report MUST include PCR values; `measurement.runtime_hash` MUST contain `PCR0`.
- **TrustZone:** The report MUST include the Trusted Application hash.

### 20.3.2 Sandbox Platforms (Trust Level 2)

| `platform.type` | Description |
|-----------------|-------------|
| `gvisor` | Google gVisor sandboxed container |
| `firecracker` | Firecracker microVM |
| `wasm` | WebAssembly sandbox (WASI or browser) |

Sandbox platforms provide kernel-level or VM-level isolation but lack hardware-rooted attestation. The `report_signature` MUST be produced by the sandbox host's signing key. Verifiers SHOULD maintain an allowlist of trusted sandbox operator keys.

### 20.3.3 Container Platforms (Trust Level 1)

| `platform.type` | Description |
|-----------------|-------------|
| `container` | OCI-compliant container with seccomp profile |

Container attestations MUST include the SHA-256 hash of the applied seccomp profile in `measurement.config_hash`. The `report_signature` is produced by the container orchestrator's signing key.

### 20.3.4 Self-Reported (Trust Level 0)

| `platform.type` | Description |
|-----------------|-------------|
| `self` | No hardware or sandbox attestation |

The executor self-reports its environment. The `report_signature` is produced by the agent's own signing key. Verifiers MUST treat Level 0 attestations as informational only and MUST NOT rely on them for security-critical decisions.

## 20.4 Measurement Fields

The `measurement` object contains cryptographic hashes of the execution environment:

```json
{
  "runtime_hash": "<SHA-256>",
  "config_hash": "<SHA-256>",
  "memory_limits": "<string, e.g. '512Mi'>",
  "network_policy_hash": "<SHA-256>",
  "filesystem_hash": "<SHA-256>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `runtime_hash` | string | REQUIRED | Hash of the runtime binary/image. For TEEs, this is the platform-specific enclave measurement. For containers, the OCI image digest. |
| `config_hash` | string | REQUIRED | Hash of the runtime configuration. For containers, includes seccomp profile, AppArmor profile, and capability set. |
| `memory_limits` | string | RECOMMENDED | Memory allocation limit in Kubernetes quantity format (e.g., `"512Mi"`, `"2Gi"`). |
| `network_policy_hash` | string | RECOMMENDED | Hash of the applied network policy. `"none"` if no network access. `"unrestricted"` if no policy applied. |
| `filesystem_hash` | string | RECOMMENDED | Hash of the filesystem manifest (list of mounted volumes and their read/write permissions). |

### 20.4.1 Measurement Computation

All hashes MUST be SHA-256 hex digests. When hashing a composite object (e.g., a network policy), the object MUST first be canonicalized with JCS (RFC 8785), then hashed.

For `runtime_hash` on TEE platforms, the value MUST be taken directly from the hardware attestation report (e.g., `MRENCLAVE` for SGX).

## 20.5 Nonce Challenge Protocol

To prevent replay of attestation reports, a challenge-response protocol is REQUIRED.

```
Verifier                          Executor
   |                                 |
   |--- NonceChallenge ------------->|
   |    { nonce: <32 random bytes>,  |
   |      timestamp: <ISO 8601> }    |
   |                                 |
   |<-- ExecutionAttestation --------|
   |    { ..., nonce: <same nonce> } |
   |                                 |
```

### 20.5.1 Nonce Generation

The verifier MUST generate a nonce of at least 32 cryptographically random bytes, encoded as a hex string (64 characters). The nonce MUST be single-use.

### 20.5.2 Nonce Freshness

The verifier SHOULD reject attestations where `timestamp` is more than 300 seconds (5 minutes) after the nonce was issued. Implementations MAY use a shorter window.

### 20.5.3 Pre-Provisioned Mode

When real-time challenge-response is impractical (e.g., asynchronous workflows), the executor MAY use a nonce derived from the `envelope_hash`:

```
nonce = SHA-256(envelope_hash || executor_public_key || floor(unix_time / 300))
```

This provides limited replay protection with a 5-minute epoch. Verifiers MUST record that pre-provisioned mode was used and MAY assign reduced trust.

## 20.6 Trust Levels

Trust levels provide a coarse classification of attestation strength:

| Level | Name | Platform Types | Attestation Root | Replay Protection |
|-------|------|---------------|-----------------|-------------------|
| 0 | Self-Reported | `self` | Agent key | Nonce only |
| 1 | Container-Isolated | `container` | Orchestrator key + seccomp hash | Nonce + config hash |
| 2 | Sandbox | `gvisor`, `firecracker`, `wasm` | Sandbox host key | Nonce + runtime hash |
| 3 | Hardware TEE | `sgx`, `tdx`, `sev`, `trustzone`, `nitro` | Hardware root of trust | Nonce + HW measurement |

### 20.6.1 Trust Level Requirements

- **Level 0:** The `measurement` fields are self-reported and unverifiable. Suitable for development and debugging.
- **Level 1:** The `config_hash` MUST include the seccomp profile hash. The orchestrator key MUST be from a known operator.
- **Level 2:** The `runtime_hash` MUST correspond to a known sandbox runtime image. The sandbox host MUST be operated by a trusted party.
- **Level 3:** The `runtime_hash` MUST match the hardware attestation report. The platform vendor's certificate chain MUST validate.

### 20.6.2 Minimum Trust Policies

Verifiers SHOULD define minimum trust level requirements per use case:

| Use Case | Recommended Minimum |
|----------|-------------------|
| Development/testing | Level 0 |
| Internal workflows | Level 1 |
| Cross-organization collaboration | Level 2 |
| Financial/legal/safety-critical | Level 3 |

## 20.7 Binding to WorkReceipt

The `WorkReceipt` (§8) gains an OPTIONAL `attestation_hash` field:

```json
{
  "type": "WorkReceipt",
  "task_id": "...",
  "agent_id": "...",
  "result_hash": "...",
  "attestation_hash": "<SHA-256 of ExecutionAttestation>",
  "signature": "..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `attestation_hash` | string | OPTIONAL | SHA-256 hex digest of the `ExecutionAttestation` object (§20.2.2) |

When present, `attestation_hash` MUST reference a valid `ExecutionAttestation` whose `envelope_hash` corresponds to the `SecurityEnvelope` associated with the same work.

### 20.7.1 Integrity Chain

The full integrity chain is:

```
WorkReceipt.attestation_hash
  → ExecutionAttestation.envelope_hash
    → SecurityEnvelope
      → Work artifacts
```

A verifier MUST walk this chain completely. If any link fails validation, the entire attestation MUST be rejected.

## 20.8 Verification Flow

A verifier checks an execution attestation through the following steps:

```
┌─────────────────────────────────────────────────┐
│ 1. NONCE CHECK                                  │
│    - Retrieve issued nonce by value              │
│    - Verify nonce was issued by this verifier    │
│    - Check timestamp freshness (< 300s)          │
│    - Mark nonce as consumed                      │
│                                                  │
│ 2. MEASUREMENT VALIDATION                        │
│    - Parse measurement fields                    │
│    - For TEE: compare runtime_hash to known-good │
│    - For container: verify config_hash includes  │
│      expected seccomp profile                    │
│    - Check memory_limits, network_policy_hash    │
│      against policy requirements                 │
│                                                  │
│ 3. PLATFORM SIGNATURE VERIFICATION               │
│    - Determine trust level from platform.type    │
│    - Level 3: validate HW attestation chain      │
│      against vendor root certificates            │
│    - Level 2: verify sandbox host key is in      │
│      trusted operator allowlist                  │
│    - Level 1: verify orchestrator signature      │
│    - Level 0: verify agent key (informational)   │
│    - Verify report_signature over JCS payload    │
│                                                  │
│ 4. BINDING VERIFICATION                          │
│    - Compute SHA-256 of ExecutionAttestation      │
│    - Compare to WorkReceipt.attestation_hash     │
│    - Verify envelope_hash matches the            │
│      SecurityEnvelope associated with the work   │
│    - Walk full integrity chain (§20.7.1)         │
│                                                  │
│ 5. POLICY EVALUATION                             │
│    - Check trust_level >= minimum required        │
│    - Evaluate measurement against policy          │
│    - Accept or reject                            │
└─────────────────────────────────────────────────┘
```

### 20.8.1 Verification Result

The verification process yields one of:

| Result | Meaning |
|--------|---------|
| `VALID` | All checks passed; trust level meets policy |
| `VALID_DEGRADED` | Attestation valid but trust level below policy minimum |
| `INVALID_NONCE` | Nonce unknown, expired, or already consumed |
| `INVALID_SIGNATURE` | Platform signature verification failed |
| `INVALID_MEASUREMENT` | Measurement does not match known-good values |
| `INVALID_BINDING` | Attestation hash chain is broken |

### 20.8.2 Error Handling

Verifiers MUST NOT partially accept attestations. If any step fails, the entire attestation MUST be treated as `INVALID` with the most specific error code.

## 20.9 Security Considerations

1. **Hardware TEE limitations.** Hardware attestation proves code identity but not code correctness. A verified enclave may still contain vulnerabilities.

2. **Side-channel attacks.** TEE attestation does not protect against all side-channel attacks. Deployments SHOULD apply additional mitigations (e.g., constant-time algorithms).

3. **Key compromise.** If a platform signing key is compromised, all attestations signed by that key become untrustworthy. Verifiers SHOULD monitor vendor security advisories and maintain revocation lists.

4. **Time-of-check vs time-of-use.** The attestation reflects the environment at measurement time. The environment could change after attestation. For Level 3, hardware TEEs provide continuous protection. For Levels 0–2, the attestation is a point-in-time snapshot.

5. **Sandbox escape.** Level 2 attestation is only as strong as the sandbox implementation. Known sandbox escapes MUST trigger revocation of affected attestations.

## 20.10 Privacy Considerations

Execution attestations may reveal information about the executor's infrastructure (hardware model, software versions, operator identity). Implementations SHOULD:

- Minimize measurement fields to those required by the verifier's policy.
- Use group signatures or zero-knowledge proofs where platform support exists (e.g., Intel EPID for SGX).
- Allow executors to negotiate which measurement fields to disclose.

## 20.11 IANA Considerations

This document defines the following values for the APS Artifact Type Registry:

| Type | Reference |
|------|-----------|
| `ExecutionAttestation` | §20.2 |

Platform type values (`sgx`, `tdx`, `sev`, `trustzone`, `nitro`, `gvisor`, `firecracker`, `wasm`, `container`, `self`) are registered in the APS Platform Type Registry.

## 20.12 References

- RFC 2119 — Key words for use in RFCs
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- Intel SGX Developer Reference
- AMD SEV-SNP Firmware ABI Specification
- AWS Nitro Enclaves Attestation Document Specification
- OCI Image Specification
- Linux seccomp BPF documentation
