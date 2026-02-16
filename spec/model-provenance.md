# §18 Model & Toolchain Provenance

## Status

Extension to Agent Passport Standard v1.1 — Draft, February 2026.

## Abstract

This section defines a provenance extension for APS WorkReceipts that
enables cryptographic supply-chain tracking of the model, toolchain,
prompt template, and security policy used during agent task execution.
It addresses model provenance attacks, prompt injection attribution,
and provides an auditable chain linking multiple WorkReceipts in
complex pipelines.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC 2119].

## 18.1 Motivation

Supply-chain attacks against AI agents operate at multiple layers:
compromised model weights, tampered runtimes, injected prompts, and
disabled guardrails.  Without cryptographic binding between a
WorkReceipt and the exact software stack that produced it, auditors
cannot attribute outputs to a known-good configuration.

This extension provides five REQUIRED fields and two OPTIONAL
mechanisms that together establish **Model & Toolchain Provenance**
for every unit of agent work.

## 18.2 Provenance Record

A `provenance` object MUST be included in every WorkReceipt that
claims conformance to APS v1.1 or later.  It is a peer of the
existing top-level WorkReceipt properties (see `work-receipt.schema.json`).

### 18.2.1 model_digest (REQUIRED)

A SHA-256 digest of the model weights or model binary used to execute
the task.

- **Format:** `sha256:<lowercase-hex>`  (64 hex characters after prefix)
- **Computation:** SHA-256 over the raw bytes of the model artifact
  (weights file, GGUF, safetensors, or equivalent).  For API-hosted
  models where the operator cannot hash weights directly, the value
  MUST be the digest published by the model provider in their
  transparency log or model card.  If no digest is available, the
  field MUST be set to `sha256:0000000000000000000000000000000000000000000000000000000000000000`
  and the `model_digest_source` field MUST be set to `"unavailable"`.

```
"model_digest": "sha256:a1b2c3d4e5f6...64 hex chars"
```

### 18.2.2 model_digest_source (RECOMMENDED)

Indicates the provenance of the `model_digest` value.

| Value          | Meaning                                                  |
|----------------|----------------------------------------------------------|
| `self`         | Operator computed the hash from local model artifacts.   |
| `provider`     | Hash obtained from the model provider's registry/card.   |
| `transparency` | Hash verified against a public transparency log.         |
| `unavailable`  | Model digest could not be obtained (see §18.2.1).        |

### 18.2.3 toolchain_digest (REQUIRED)

A SHA-256 digest of the full toolchain configuration: runtime,
libraries, framework version, and any plugins loaded during execution.

- **Format:** `sha256:<lowercase-hex>`
- **Computation:** Canonicalize a JSON object containing at minimum
  `{ "runtime", "runtime_version", "framework", "framework_version",
  "plugins": [...] }` using JCS [RFC 8785], then SHA-256 the result.

### 18.2.4 prompt_template_hash (REQUIRED)

A Keccak-256 hash of the system prompt or prompt template active
during task execution.

- **Format:** `keccak256:<lowercase-hex>`
- **Rationale:** Keccak-256 is chosen (rather than SHA-256) to
  provide domain separation from the other digest fields and to align
  with Ethereum ecosystem tooling for on-chain anchoring.
- **Computation:** Keccak-256 over the UTF-8 encoding of the full
  system prompt text, including any template variables in their
  unexpanded form (i.e., `{{variable}}` literals).
- **Security:** This field binds the WorkReceipt to a specific prompt,
  preventing prompt injection attribution attacks where a malicious
  actor replaces the system prompt and claims the output was produced
  under the original instructions.

### 18.2.5 policy_hash (REQUIRED)

A SHA-256 hash of the security policy and guardrails configuration
active during execution.

- **Format:** `sha256:<lowercase-hex>`
- **Computation:** Canonicalize the policy document (JSON or YAML
  converted to JSON) using JCS [RFC 8785], then SHA-256.
- **Relationship to SecurityEnvelope:** The `policy_hash` SHOULD
  match or incorporate the `envelope_hash` from the active
  SecurityEnvelope (§7).  If the agent operates under multiple
  policy layers, they MUST be merged into a single canonical document
  before hashing.

### 18.2.6 runtime_version (REQUIRED)

The semantic version string of the agent runtime.

- **Format:** SemVer 2.0.0 (`MAJOR.MINOR.PATCH`, with optional
  pre-release and build metadata).
- **Example:** `"1.4.2"`, `"2.0.0-rc.1+build.9a3f"`

## 18.3 Provenance Chain

Complex tasks often span multiple WorkReceipts — e.g., a planning
agent delegates sub-tasks to specialist agents.  The **Provenance
Chain** links these records into an auditable DAG.

### 18.3.1 parent_receipt_ids (OPTIONAL)

An array of `receipt_id` values (UUIDs) identifying the WorkReceipts
whose outputs were consumed as inputs to the current task.

```json
"parent_receipt_ids": [
  "550e8400-e29b-41d4-a716-446655440000",
  "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
]
```

### 18.3.2 pipeline_id (OPTIONAL)

A UUID identifying the overall pipeline or multi-step workflow.  All
WorkReceipts in the same pipeline SHOULD share this value.

### 18.3.3 step_index (OPTIONAL)

A zero-based integer indicating the position of this WorkReceipt
within the pipeline.  When `parent_receipt_ids` forms a DAG rather
than a linear chain, `step_index` reflects topological order.

### 18.3.4 Verification

A verifier reconstructing the provenance chain MUST:

1. Retrieve all WorkReceipts sharing the same `pipeline_id`.
2. Verify each receipt's `proof` (Ed25519Signature2020, §5).
3. Verify that each receipt's `parent_receipt_ids` reference valid,
   signed WorkReceipts within the same pipeline.
4. Verify that the `provenance` fields (model_digest, toolchain_digest,
   etc.) are consistent with the operator's published configuration
   or transparency log entries.

## 18.4 Watermark Detection (OPTIONAL)

For AI-generated content (text, images, audio, video), an agent MAY
include watermark metadata compatible with the C2PA (Coalition for
Content Provenance and Authenticity) standard.

### 18.4.1 watermark Object

```json
"watermark": {
  "standard": "C2PA",
  "version": "2.1",
  "manifest_uri": "https://example.com/c2pa/manifest/abc123",
  "content_hash": "sha256:...",
  "signer_did": "did:web:agent.example.com"
}
```

| Field           | Type   | Req.     | Description                                    |
|-----------------|--------|----------|------------------------------------------------|
| `standard`      | string | REQUIRED | Watermark standard identifier (e.g., `"C2PA"`). |
| `version`       | string | REQUIRED | Version of the watermark standard.              |
| `manifest_uri`  | string | OPTIONAL | URI to the full C2PA manifest.                  |
| `content_hash`  | string | REQUIRED | SHA-256 hash of the watermarked content.        |
| `signer_did`    | DID    | OPTIONAL | DID of the entity that signed the watermark.    |

### 18.4.2 Relationship to WorkReceipt Proof

The watermark `content_hash` SHOULD be included in the WorkReceipt
event's `evidence` map under the key `"watermark_content_hash"`.
This binds the watermark to the receipt's signature chain.

## 18.5 Full Provenance Example

```json
{
  "@context": "https://agentpassport.org/v1.1",
  "spec_version": "1.1.0",
  "type": "WorkReceipt",
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "agent_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "client_did": "did:web:client.example.com",
  "agent_snapshot": {
    "version": 3,
    "hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  },
  "provenance": {
    "model_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "model_digest_source": "provider",
    "toolchain_digest": "sha256:7d793037a076810291129e8be30f28610d5e2631a58c2ac66c4706b77a3a4f09",
    "prompt_template_hash": "keccak256:4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    "policy_hash": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "runtime_version": "1.4.2",
    "parent_receipt_ids": [],
    "pipeline_id": "9f86d081-884c-4d7a-9e28-3b6e7a1c0e82",
    "step_index": 0,
    "watermark": {
      "standard": "C2PA",
      "version": "2.1",
      "content_hash": "sha256:d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    }
  },
  "events": [
    {
      "type": "submit",
      "timestamp": "2026-02-16T01:00:00Z",
      "payload_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      "signature": "z3hQ4r...",
      "evidence": {
        "watermark_content_hash": "sha256:d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
      }
    }
  ],
  "receipt_hash": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-16T01:00:01Z",
    "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndTn..."
  }
}
```

## 18.6 Security Considerations

1. **Model Substitution:** Without `model_digest`, an operator could
   swap a safety-tuned model for an unrestricted one while claiming
   compliance.  Verifiers SHOULD cross-reference `model_digest`
   against known-good registries.

2. **Prompt Injection Attribution:** The `prompt_template_hash` field
   ensures that if an attacker injects a different system prompt, the
   hash mismatch is detectable during audit.

3. **Toolchain Tampering:** The `toolchain_digest` binds the execution
   environment.  Operators SHOULD publish their toolchain manifests
   in a transparency log per [RFC 6962].

4. **Provenance Chain Forgery:** An attacker could fabricate
   `parent_receipt_ids` pointing to legitimate WorkReceipts.
   Verifiers MUST check that the referenced receipts' `agent_did`
   or `pipeline_id` values are consistent with the claimed workflow.

5. **Unavailable Digests:** When `model_digest_source` is
   `"unavailable"`, verifiers SHOULD treat the WorkReceipt with
   reduced trust and MAY reject it depending on policy.

## 18.7 IANA Considerations

This document registers no new IANA values.  The `provenance` object
is scoped within the APS namespace (`https://agentpassport.org/v1.1`).

## 18.8 References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC 8785] Rundgren, A., Jordan, B., Erdtman, S., "JSON
  Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- [RFC 6962] Laurie, B., Langley, A., Kasper, E., "Certificate
  Transparency", RFC 6962, June 2013.
- [RFC 8032] Josefsson, S., Liusvaara, I., "Edwards-Curve Digital
  Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- [C2PA] Coalition for Content Provenance and Authenticity,
  "C2PA Technical Specification", v2.1, 2025.
- [APS §5] WorkReceipt Proof, Agent Passport Standard v1.0.
- [APS §7] SecurityEnvelope, Agent Passport Standard v1.0.
