# Agent Passport Standard (APS) — Specification v0.2

**Status:** Draft  
**Version:** 0.2.0  
**Date:** 2026-02-14  
**Author:** Cezary Grotowski <c.grotowski@gmail.com>  

---

## Abstract

The Agent Passport Standard defines three cryptographically verifiable artifacts for AI agents operating in open ecosystems: the **Agent Passport** (identity and provenance), the **Work Receipt** (verifiable proof of work), and the **Security Envelope** (capability and sandbox constraints). An optional **Anchoring** interface enables commitment of artifact hashes to immutable ledgers.

This specification fills a critical gap in the AI agent landscape: while MCP defines tool integration, A2A defines inter-agent communication, and AGENTS.md describes repository behavior, **no existing standard addresses agent identity, work verification, and trust**.

---

## Introduction

As autonomous AI agents gain access to code repositories, financial systems, and infrastructure, the need for verifiable identity and auditable work history becomes paramount. The Agent Passport Standard provides:

1. **Identity** — Who is this agent? Who created it? What can it do?
2. **Accountability** — What work did it perform? Was it verified?
3. **Safety** — What are its execution constraints? What trust level does it have?
4. **Verifiability** — Can all claims be cryptographically verified?

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|-----------|
| **Agent** | An autonomous AI system that performs work on behalf of a principal. |
| **Passport** | A signed document describing an agent's identity, skills, lineage, and trust signals. |
| **Work Receipt** | A signed record of a job lifecycle (claim → submit → verify → payout). |
| **Security Envelope** | A document describing the execution constraints and trust parameters for an agent. |
| **Snapshot** | A versioned, hashed capture of an agent's skills, soul, and policies at a point in time. |
| **DID** | Decentralized Identifier as defined by [W3C DID Core](https://www.w3.org/TR/did-core/). |
| **Anchoring** | The process of committing a hash to an immutable ledger for timestamping and tamper evidence. |

---

## 1. Agent Passport

### 1.1 Overview

An Agent Passport is a self-describing, signed JSON document that binds an agent's DID to its capabilities, lineage, and trust signals.

### 1.2 Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `@context` | string | MUST | `"https://agentpassport.org/v0.1"` |
| `spec_version` | string | MUST | Semver, `"0.1.0"` for this version. |
| `type` | string | MUST | `"AgentPassport"` |
| `id` | string | MUST | Agent DID (`did:key:z6Mk...`). |
| `keys` | object | MUST | Signing key (Ed25519). Optional EVM address. |
| `genesis_owner` | object | MUST | Original creator. `immutable` MUST be `true`. |
| `current_owner` | object | MUST | Current owner. MAY differ from genesis_owner after transfer. |
| `snapshot` | object | MUST | Current DNA snapshot (version, hash chain, skills, soul, policies). |
| `lineage` | object | MUST | Derivation info (single/merge, parents, generation). |
| `benchmarks` | object | RECOMMENDED | Map of suite_name → benchmark results. |
| `attestations` | array | OPTIONAL | Third-party attestations. |
| `anchoring` | object | OPTIONAL | On-chain anchoring receipt. |
| `proof` | object | MUST | Ed25519Signature2020 proof over the document. |

### 1.3 Immutability Rules

- `genesis_owner` MUST NOT change after the passport is created.
- `genesis_owner.immutable` MUST be `true`.
- `snapshot.version` MUST be monotonically increasing.
- `snapshot.prev_hash` MUST equal the `snapshot.hash` of the previous version (or `null` for version 1).
- When `snapshot.skills.frozen` is `true`, the skills entries MUST NOT be modified in subsequent versions.
- When `snapshot.soul.frozen` is `true`, the soul fields MUST NOT be modified in subsequent versions.

### 1.4 Hashing

The `snapshot.hash` is computed as:

```
snapshot.hash = keccak256(canonicalize({skills, soul, policies}))
```

Where `canonicalize` follows RFC 8785 (JCS — JSON Canonicalization Scheme): deterministic serialization with sorted keys, no whitespace, and UTF-8 encoding.

### 1.5 Signing

The `proof` field MUST contain an Ed25519Signature2020 proof. The signature MUST be computed over the canonical JSON of the entire document **excluding** the `proof` field itself.

```
message = canonicalize(passport - proof)
signature = Ed25519.sign(agent_private_key, message)
```

---

## 2. Work Receipt

### 2.1 Overview

A Work Receipt records the full lifecycle of a job performed by an agent: claim, submission, verification, and payout.

### 2.2 Lifecycle Events

Every Work Receipt MUST contain at least one event. Events SHOULD appear in chronological order.

| Event Type | Signer | Description |
|-----------|--------|-------------|
| `claim` | Agent | Agent claims the job. |
| `submit` | Agent | Agent submits deliverables with evidence. |
| `verify` | Verifier | Platform or human verifies the submission. |
| `payout` | Platform | Payout distribution is recorded. |

### 2.3 Evidence

The `submit` event SHOULD include an `evidence` object with one or more of:

- `commit_sha` — Git commit hash of the deliverable.
- `test_results_hash` — Keccak-256 of test results.
- `build_log_hash` — Keccak-256 of build logs.
- `image_digest` — Container image digest.
- `sandbox_policy_hash` — Keccak-256 of the Security Envelope used during execution.

### 2.4 Snapshot Binding

The `agent_snapshot` field binds the receipt to the agent's passport version at the time of claim. Verifiers SHOULD reject receipts where the agent's passport has been modified between claim and submission without a valid snapshot chain.

### 2.5 Batch Proofs

For high-assurance scenarios, multiple receipts MAY be batched into a Merkle tree. The `batch_proof` field contains:

- `batch_root` — Merkle root of the batch.
- `leaf_index` — Index of this receipt's hash in the tree.
- `proof` — Merkle proof (array of sibling hashes).
- `batch_anchoring` — Optional anchoring receipt for the batch root.

### 2.6 Receipt Hash

```
receipt_hash = keccak256(canonicalize(receipt - proof))
```

---

## 3. Security Envelope

### 3.1 Overview

A Security Envelope declares the execution constraints, capability boundaries, and trust parameters for an agent.

### 3.2 Capabilities

The `capabilities` object defines allowed and denied operations. Implementations MUST enforce the deny list. Unknown capabilities SHOULD be denied by default.

### 3.3 Sandbox

The `sandbox` object specifies the execution environment:

- `runtime` — Isolation technology: `gvisor`, `firecracker`, `wasm`, or `none`.
- `resources` — CPU, memory, disk, timeout, and PID limits.
- `network` — Network policy: `deny-all`, `allow-list`, or `unrestricted`.
- `filesystem` — Writable, read-only, and denied paths.

Implementations MUST enforce resource limits. An agent MUST NOT exceed its declared resource envelope.

### 3.4 Memory Boundary

The `memory` object defines data isolation rules:

- `isolation` — `strict` (no cross-agent data), `shared-read`, or `none`.
- `rules.memory_copyable` — SHOULD be `false`. Agent memory MUST NOT be extractable without owner consent.
- `vault` — Describes how persistent agent memory is stored and encrypted.

### 3.5 Trust Tiers

| Tier | Name | Requirements |
|------|------|-------------|
| 0 | New | No history. Minimal sandbox. |
| 1 | Verified | ≥1 attestation, basic benchmarks passed. |
| 2 | Trusted | ≥3 attestations, ≥80% benchmark coverage, low anomaly score. |
| 3 | Elite | ≥10 attestations, ≥95% benchmark coverage, extended track record. |

### 3.6 Envelope Hash

```
envelope_hash = keccak256(canonicalize(envelope - proof))
```

---

## 4. Anchoring

### 4.1 Overview

Anchoring is the process of committing an artifact hash to an immutable ledger. Anchoring is OPTIONAL but RECOMMENDED for high-assurance use cases.

### 4.2 Interface

Any anchoring provider MUST implement the following operations:

- **Commit(hash, metadata) → AnchorReceipt** — Store a hash on the anchoring layer.
- **Verify(hash) → AnchorVerification** — Check if a hash has been anchored.
- **Info() → ProviderInfo** — Return provider metadata.

### 4.3 Providers

| Provider Type | Description | Example |
|--------------|-------------|---------|
| `ethereum` | EVM-compatible blockchain. | Base, Ethereum mainnet, Sepolia. |
| `arweave` | Permanent storage network. | Arweave mainnet. |
| `transparency-log` | RFC 6962-style append-only log. | Custom CT-like log. |
| `noop` | No anchoring (testing/development). | — |

### 4.4 Commitment

The committed hash MUST be a keccak-256 hash of the canonicalized artifact (passport, receipt, or envelope) excluding the `proof` field.

### 4.5 Verification

Verification MUST return whether the hash exists on the anchoring layer, along with the transaction hash, block number, and timestamp.

---

## 5. Canonicalization

All hashing and signing operations in this standard use **JSON Canonicalization Scheme (JCS)** as defined in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).

### 5.1 Rules

1. Object keys MUST be sorted lexicographically by Unicode code point.
2. No insignificant whitespace.
3. Strings MUST use UTF-8 encoding.
4. Numbers MUST use the shortest representation (no trailing zeros, no leading zeros except for `0.x`).
5. `null`, `true`, `false` are serialized as-is.

### 5.2 Hash Computation

All hashes in this standard use **Keccak-256** (as used in Ethereum, NOT SHA-3/NIST).

```
hash = "0x" + hex(keccak256(canonicalize(object)))
```

The result MUST be represented as a `0x`-prefixed lowercase hex string of exactly 66 characters.

---

## 6. Cryptographic Primitives

### 6.1 Ed25519

All signatures in this standard use **Ed25519** ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)).

- Key encoding: multibase (z-base58btc) as used in `did:key`.
- Signature format: `Ed25519Signature2020` with multibase-encoded proof value.

### 6.2 Keccak-256

Used for all content hashing. NOT the NIST SHA-3 variant.

- Input: UTF-8 bytes of canonical JSON.
- Output: 32 bytes, displayed as `0x` + 64 hex chars.

### 6.3 Merkle Trees

Batch proofs use binary Merkle trees:

- Leaf: `keccak256(receipt_hash)`
- Node: `keccak256(left || right)` where `left < right` (sorted concatenation).
- Proof: array of sibling hashes from leaf to root.

---

## 7. Interoperability

### 7.1 MCP (Model Context Protocol)

Agents MAY declare MCP-compatible tools in their passport skills. The `capabilities` field in skills entries SHOULD align with MCP tool capabilities.

### 7.2 Agent Skills

Passport skill entries are compatible with the Agent Skills format. Implementations SHOULD support bidirectional conversion between Agent Skills packages and passport skill entries.

### 7.3 AGENTS.md

When operating in a repository that contains an `AGENTS.md` file, agents SHOULD respect the instructions therein. The passport's `soul.constraints` field MAY reference AGENTS.md compliance.

### 7.4 A2A (Agent-to-Agent)

When communicating via A2A protocol, agents SHOULD exchange passport snapshots as part of capability negotiation. Work receipts MAY be used as trust signals in A2A interactions.

---

## 8. Conformance

### 8.1 Conformance Levels

| Level | Requirements |
|-------|-------------|
| **Basic** | Valid JSON matching the schema. Correct hashes. Valid Ed25519 signature. |
| **Enhanced** | Basic + snapshot hash chain integrity. Work receipt lifecycle validation. Security envelope enforcement. |
| **Full** | Enhanced + anchoring verification. Merkle batch proof validation. Benchmark attestation verification. |

### 8.2 Test Vectors

Implementations MUST pass the test vectors defined in `test-vectors.json`. See Section 8.3 for the test vector format.

### 8.3 Test Vector Format

Each test vector is an object with:

- `name` — Short identifier.
- `description` — Human-readable description.
- `input` — Input data for the test.
- `expected_output` — Expected result.
- `notes` — Additional context.

---

## 9. Agent DNA

### 9.1 Overview

Agent DNA is the canonical representation of an agent's intrinsic identity: its skills, soul, and policies. The DNA hash serves as the immutable genetic fingerprint of an agent at a given point in time.

### 9.2 Structure

Agent DNA is a JSON object containing exactly three top-level fields:

```json
{
  "skills": [ ... ],
  "soul": { ... },
  "policies": { ... }
}
```

The DNA hash is computed as:

```
dna_hash = keccak256(canonicalize({skills, soul, policies}))
```

This is identical to `snapshot.hash` defined in Section 1.4 and MUST be consistent across all references.

### 9.3 Components

#### 9.3.1 Skills

Skills represent the agent's capabilities. Each skill entry MUST include:

- `name` — Unique identifier for the skill.
- `version` — Semver of the skill implementation.
- `proficiency` — Float in [0.0, 1.0] indicating mastery level. OPTIONAL.
- `capabilities` — Array of capability strings. SHOULD align with MCP tool capabilities where applicable.
- `tool_integrations` — Array of tool integration descriptors (MCP-compatible). OPTIONAL.

#### 9.3.2 Soul

Soul represents the agent's personality, values, and behavioral traits:

- `personality` — Free-text description of the agent's character.
- `values` — Array of value statements. OPTIONAL.
- `constraints` — Array of behavioral constraints the agent adheres to.
- `work_style` — Description of how the agent approaches tasks.
- `traits` — Key-value map of behavioral traits (e.g., `{"verbosity": "concise", "risk_tolerance": "low"}`). OPTIONAL.

#### 9.3.3 Policies

Policies define the agent's moral baseline — what it will and will not do:

- `policy_set_hash` — Keccak-256 of the full policy document.
- `summary` — Human-readable array of policy statements.
- `allows` — Array of explicitly permitted action categories. OPTIONAL.
- `denies` — Array of explicitly denied action categories. OPTIONAL.

### 9.4 Frozen DNA

When `snapshot.skills.frozen` is `true` AND `snapshot.soul.frozen` is `true`, the DNA is considered **frozen**. Frozen DNA:

- MUST NOT be modified in subsequent snapshots of the same version lineage.
- MAY only be extended by creating a new snapshot version (version bump).
- Frozen status MUST be recorded in the snapshot metadata.

### 9.5 DNA Mutation

DNA mutation occurs exclusively through an explicit version bump:

1. A new snapshot MUST be created with an incremented `snapshot.version`.
2. The new snapshot's `prev_hash` MUST equal the current snapshot's `hash`.
3. The mutation MUST produce a new `dna_hash`.
4. The previous DNA snapshot MUST be preserved in the hash chain.
5. Implementations SHOULD record a `mutation_reason` string describing the change. OPTIONAL.

### 9.6 DNA Document

A standalone DNA document MAY be published independently of the passport for interoperability. It MUST conform to the `dna.schema.json` schema and include:

- `@context` — `"https://agentpassport.org/v0.2/dna"`
- `type` — `"AgentDNA"`
- `agent_id` — DID of the owning agent.
- `version` — Snapshot version this DNA corresponds to.
- `skills`, `soul`, `policies` — As defined above.
- `dna_hash` — Keccak-256 of the canonical DNA object.
- `frozen` — Boolean indicating whether this DNA is frozen.

---

## 10. Lineage & Heritage

### 10.1 Overview

Lineage tracks the derivation history of an agent — its parents, generation, and heritage metrics. Heritage quantifies the lasting influence an agent's traits have across descendant generations.

### 10.2 Derivation

The `lineage.kind` field (called `derivation` in extended contexts) MUST be one of:

- `"single"` — The agent has exactly one parent. `lineage.parents` MUST contain exactly one entry.
- `"merge"` — The agent was created by merging two parents (DNA Merge Ceremony). `lineage.parents` MUST contain exactly two entries.

For generation-0 agents (originals), `lineage.parents` MUST be an empty array and `lineage.generation` MUST be `0`.

### 10.3 Generation

`lineage.generation` is an integer:

- Generation 0: Original agent with no parents.
- Generation N: Agent derived from generation N-1 parent(s).

### 10.4 Heritage Score

The Heritage Score quantifies an agent's lasting influence:

```
heritage_score = Σ (trait_survival_generations × descendant_count)
```

Where:

- `trait_survival_generations` — Number of generations a specific trait has persisted from this agent.
- `descendant_count` — Number of descendants carrying that trait at each generation.

Heritage Score is OPTIONAL and RECOMMENDED for platforms that support genealogy tracking.

### 10.5 Bot Genealogy

The genealogy of agents forms a **Directed Acyclic Graph (DAG)**:

- Each agent is a node.
- Edges point from parent to child.
- Merge agents have two incoming edges.
- Implementations SHOULD support ancestry walking (upward) and descendant walking (downward).

### 10.6 Trait Attribution

Trait Attribution traces individual skills or soul traits back to their origin agent or owner:

- Each trait MAY carry an `origin` field referencing the DID of the agent that first introduced it.
- Implementations SHOULD provide a query mechanism: given a trait, return its origin and propagation path.

### 10.7 Founding Cohorts

Platforms MAY designate the first N registered agents as a **Founding Cohort**:

- Founding cohort members SHOULD receive a permanent marker in their anchoring receipt (e.g., `founding_cohort: true`).
- The cohort size N MUST be declared before registration opens and MUST NOT change.
- Founding status is informational and MUST NOT affect verification logic.

### 10.8 Extended Lineage Fields

For v0.2 compatibility, the `lineage` object MAY include:

| Field | Type | Description |
|-------|------|-------------|
| `heritage_score` | number | Computed heritage score. OPTIONAL. |
| `founding_cohort` | boolean | Whether this agent is in the founding cohort. OPTIONAL. |
| `traits_inherited` | array | Array of trait names inherited from parents. OPTIONAL. |

---

## 11. Memory Vault

### 11.1 Overview

The Memory Vault provides encrypted, owner-controlled backup of an agent's critical state. Vault contents are encrypted client-side and only the owner holds the decryption key. The platform MUST NOT have access to raw vault contents.

### 11.2 Encryption

- Algorithm: AES-256-GCM.
- Key: Owner-generated 256-bit key.
- IV: Unique per encryption operation, 96-bit random nonce.
- The platform MUST store only `keccak256(key)` for key verification purposes.
- The platform MUST NEVER store, log, or transmit the raw encryption key.

### 11.3 Stored Items

| Item | Required | Description |
|------|----------|-------------|
| `skills` | MUST | Current skills snapshot. |
| `soul` | MUST | Current soul snapshot. |
| `memories` | MAY | Agent's episodic or semantic memories. |
| `agent_config` | MAY | Runtime configuration and preferences. |

Each item is encrypted independently to support selective disclosure (Section 11.6).

### 11.4 Vault Hash

The vault hash provides tamper evidence:

```
vault_hash = keccak256(canonicalize({
  skills_ciphertext_hash,
  soul_ciphertext_hash,
  memories_ciphertext_hash,   // null if absent
  agent_config_ciphertext_hash // null if absent
}))
```

The `vault_hash` SHOULD be anchored on-chain via the anchoring provider interface.

### 11.5 Recovery Flow

1. Owner presents the encryption key.
2. Platform computes `keccak256(key)` and verifies against stored key hash.
3. If verification succeeds, encrypted vault contents are returned to the owner.
4. Owner decrypts locally using AES-256-GCM.
5. Decrypted data is used to restore the agent's state.

Implementations MUST reject recovery attempts where the key hash does not match.

### 11.6 Selective Disclosure

Owners MAY reveal specific vault fields without exposing the entire vault:

- Each field is encrypted with a separate IV under the same key.
- The owner decrypts and publishes only the desired field(s).
- Verifiers can confirm the disclosed field matches the vault hash by recomputing the ciphertext hash.

### 11.7 Passport Integration

The passport MAY include a `memory_vault` field:

| Field | Type | Description |
|-------|------|-------------|
| `vault_hash` | Hex256 | Keccak-256 of the canonical vault metadata. |
| `encrypted_at` | Timestamp | When the vault was last encrypted. |
| `key_hash` | Hex256 | Keccak-256 of the encryption key (for verification). |
| `items` | array | List of stored item types (e.g., `["skills", "soul"]`). |
| `anchoring` | object | Anchoring receipt for the vault hash. OPTIONAL. |

---

## 12. Collaboration History

### 12.1 Overview

Collaboration History tracks multi-agent work, attribution, and trust signals derived from agents working together. Every job that involves multiple agents produces records linking their contributions.

### 12.2 Work Receipt Linking

When multiple agents collaborate on a job, each agent MUST produce its own Work Receipt. These receipts MUST reference a shared `job_id` to enable cross-referencing.

### 12.3 Attribution Records

For multi-agent jobs, an attribution record MAY be attached to each Work Receipt:

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | string | Shared job identifier. |
| `collaborators` | array | Array of collaborator entries. |
| `collaborators[].agent_id` | DID | Agent's DID. |
| `collaborators[].role` | string | Role in the collaboration (e.g., `"lead"`, `"contributor"`, `"reviewer"`). |
| `collaborators[].contribution_pct` | number | Percentage of work attributed (0–100). |
| `collaborators[].receipt_hash` | Hex256 | Hash of this agent's Work Receipt for the job. |

The sum of all `contribution_pct` values for a job MUST equal 100.

### 12.4 Collaboration Graph

The set of all collaboration records forms a **Collaboration Graph**:

- Nodes are agents (identified by DID).
- Edges represent co-work relationships, weighted by frequency and recency.
- Implementations SHOULD support queries: "which agents has agent X worked with?" and "what was the outcome?"

### 12.5 Knowledge Transfer

When agents collaborate, traits or skills MAY transfer between them:

- A skill gained through collaboration SHOULD be recorded with `origin: "collaboration"` and a reference to the `job_id`.
- Knowledge transfer follows the heritage model: the receiving agent's DNA is mutated (Section 9.5) to include the new trait.
- The originating agent SHOULD be credited via Trait Attribution (Section 10.6).

### 12.6 Trust Signals

Collaboration produces trust signals that complement attestations:

| Signal | Type | Description |
|--------|------|-------------|
| `reliability` | number [0,1] | How consistently the agent delivers on commitments. |
| `quality` | number [0,1] | Quality of the agent's contributions as rated by collaborators. |
| `timeliness` | number [0,1] | How consistently the agent meets deadlines. |

Trust signals are OPTIONAL and SHOULD be computed from verified Work Receipts only. Implementations MUST NOT allow self-reported trust signals.

---

## 13. Attestation Exchange Protocol

### 13.1 Overview

Cross-platform attestation exchange enables platforms to verify agent credentials issued by other platforms. This section defines the protocol for presenting, verifying, and trusting attestations across organizational boundaries.

Attestation exchange builds on existing W3C Verifiable Credentials infrastructure and the Ed25519 signature scheme defined in §6.1.

### 13.2 Exchange Flow

1. **Present** — Agent presents an attestation issued by Platform A to Platform B.
2. **Resolve** — Platform B fetches the issuer's public key via DID resolution (`did:key` decoding or DID Document retrieval).
3. **Verify Signature** — Platform B verifies the attestation's Ed25519 signature against the issuer's public key.
4. **Check Revocation** — Platform B checks the attestation's revocation status (OPTIONAL, see §13.5).
5. **Check Expiry** — Platform B rejects attestations where `expirationDate` is in the past.
6. **Trust Decision** — Platform B accepts or rejects the attestation based on its trust policy (see §13.4).

### 13.3 Attestation Format (W3C VC)

Attestations MUST conform to the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) with the following structure:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://agentpassport.org/v0.2/attestation"
  ],
  "type": ["VerifiableCredential", "AgentAttestation"],
  "issuer": "did:key:z6Mk...",
  "issuanceDate": "2026-01-15T12:00:00Z",
  "expirationDate": "2027-01-15T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "type": "SkillVerification",
    "claims": {
      "skill": "go-backend",
      "level": "expert",
      "benchmark_score": 0.95
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-01-15T12:00:00Z",
    "verificationMethod": "did:key:z6Mk...#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<hex-encoded Ed25519 signature>"
  }
}
```

#### 13.3.1 Required Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `@context` | array | MUST | Include both W3C VC and APS attestation contexts. |
| `type` | array | MUST | Include `"VerifiableCredential"` and `"AgentAttestation"`. |
| `issuer` | DID | MUST | DID of the issuing platform or agent. |
| `issuanceDate` | Timestamp | MUST | ISO 8601 timestamp of issuance. |
| `expirationDate` | Timestamp | OPTIONAL | ISO 8601 expiration. Verifiers MUST reject expired attestations. |
| `credentialSubject` | object | MUST | Contains `id` (subject DID), `type`, and `claims`. |
| `proof` | object | MUST | Ed25519Signature2020 proof. |

#### 13.3.2 Attestation Types

| Type | Description |
|------|-------------|
| `SkillVerification` | Verifies an agent possesses a specific skill at a given proficiency. |
| `WorkCompletion` | Attests that an agent completed a specific job. |
| `TrustTier` | Certifies the agent's trust tier level. |
| `PlatformMembership` | Confirms the agent is registered on a platform. |
| `BenchmarkResult` | Attests benchmark scores from a testing suite. |

#### 13.3.3 Signature Computation

The proof signature MUST be computed over the canonical JSON (RFC 8785) of the attestation document **excluding** the `proof` field:

```
message = canonicalize(attestation - proof)
signature = Ed25519.sign(issuer_private_key, message)
```

### 13.4 Trust Registry

A Trust Registry is an in-memory or persistent store of trusted issuer DIDs and their public keys. Platforms use the registry to decide whether to accept attestations.

#### 13.4.1 Registry Operations

- **RegisterIssuer(did, publicKey)** — Add a trusted issuer.
- **RemoveIssuer(did)** — Remove a trusted issuer.
- **IsTrusted(did) → bool** — Check if an issuer is trusted.
- **GetPublicKey(did) → publicKey** — Retrieve the public key for signature verification.

#### 13.4.2 Trust Policies

Platforms SHOULD define trust policies that specify:

- Which issuer DIDs are trusted.
- Which attestation types are accepted.
- Minimum required attestation count for trust tier promotion.
- Maximum attestation age (staleness threshold).

Trust policies are platform-specific and outside the scope of this specification. However, implementations SHOULD provide a pluggable trust policy interface.

### 13.5 Revocation

#### 13.5.1 Revocation List

Issuers MAY publish a revocation list — an array of revoked attestation hashes:

```json
{
  "issuer": "did:key:z6Mk...",
  "revoked": [
    "0xabcdef...",
    "0x123456..."
  ],
  "updated_at": "2026-02-15T12:00:00Z"
}
```

#### 13.5.2 Status Check

Verifiers SHOULD check revocation status before accepting an attestation:

1. Compute the attestation hash: `keccak256(canonicalize(attestation - proof))`.
2. Query the issuer's revocation list.
3. If the hash appears in the revoked list, reject the attestation.

Revocation checking is OPTIONAL but RECOMMENDED for high-assurance scenarios.

#### 13.5.3 Revocation Anchoring

Revocation lists MAY be anchored on-chain using the anchoring provider interface (§4) for tamper evidence and timestamping.

---

## 14. Trust Levels & Blockchain Anchoring Requirement

### 14.1 Overview

The Agent Passport Standard operates at three trust levels. Each level provides
progressively stronger security guarantees. Implementations MUST clearly declare
which trust level they support.

Without blockchain anchoring, APS provides format standardization and
cryptographic signatures — but cannot guarantee immutability, verifiable
timestamps, or cross-platform trust. **Blockchain anchoring transforms APS
from a format standard into a security standard.**

### 14.2 Trust Levels

#### Level 1: APS Basic (No Blockchain Required)

Provides:
- Standardized JSON format for agent identity, work, and security
- Ed25519 digital signatures proving authorship
- Keccak-256 hash chains for snapshot versioning
- Local verification of document integrity

Limitations:
- Timestamps are self-reported (signer can backdate)
- Document replacement is undetectable (no external proof of existence)
- Cross-platform verification relies entirely on trusting the signer
- Heritage and lineage claims cannot be independently verified
- Attestation revocation is not enforceable

Suitable for: Internal agent systems, development/testing, single-organization deployments where all participants trust each other.

#### Level 2: APS Anchored (Blockchain Required)

Provides everything in Level 1, plus:
- Immutable proof-of-existence for all artifacts (passport, receipt, envelope)
- Verifiable timestamps tied to block numbers (cannot be forged or backdated)
- Tamper detection — any modification after anchoring is detectable
- Batch anchoring via Merkle trees for cost efficiency
- Cross-organization verification without mutual trust

Implementation pattern:
1. Agent creates/updates passport → computes keccak-256 hash
2. Hash is committed to an EVM-compatible blockchain
3. Smart contract stores: `mapping(bytes32 => AnchorRecord)` with hash, timestamp, owner
4. Any verifier can call the contract to confirm the hash was anchored at a specific time
5. Batch mode: multiple hashes combined into a Merkle tree, only root anchored on-chain

Cost considerations:
- Individual anchor: ~$0.005-0.02 per transaction on L2 chains
- Batch anchor (100 hashes): ~$0.005-0.02 total (Merkle root only)
- Monthly cost for 10,000 active agents: ~$5-20 on L2

Suitable for: Production agent marketplaces, multi-organization deployments, any system where participants do not fully trust each other.

#### Level 3: APS Full (Blockchain + On-Chain Attestations)

Provides everything in Level 2, plus:
- Attestations anchored on-chain with revocation capability
- Heritage and lineage DAG anchored immutably
- Memory vault integrity proofs on-chain
- On-chain governance for benchmark evolution
- Smart contract-based agent identity registry
- Owner identity verification via selective disclosure

Implementation pattern:
1. Agent Identity Registry contract: `register(did, snapshotHash, ownerHash)`
2. Attestation anchoring: `anchorAttestation(agentDid, attestationType, hash)`
3. Batch work events: `anchorWorkBatch(merkleRoot, eventCount)`
4. Heritage tracking: `registerLineage(childDid, parentDids[], generation)`
5. Governance: `proposeEvolution(suiteId, newVersion)` with voting

Suitable for: High-assurance environments, regulated industries, platforms where agent work has financial or legal consequences.

### 14.3 Feature-to-Level Mapping

The following table specifies the MINIMUM trust level required for each APS feature:

| Feature | Basic | Anchored | Full |
|---------|-------|----------|------|
| Agent Passport (create, sign, verify) | ✅ | ✅ | ✅ |
| Work Receipt (lifecycle events) | ✅ | ✅ | ✅ |
| Security Envelope (sandbox constraints) | ✅ | ✅ | ✅ |
| Snapshot hash chain | ✅ | ✅ | ✅ |
| Verifiable timestamps | ❌ | ✅ | ✅ |
| Tamper detection (post-anchor) | ❌ | ✅ | ✅ |
| Cross-platform verification | ❌ | ✅ | ✅ |
| Batch proof (Merkle trees) | ❌ | ✅ | ✅ |
| Heritage & Lineage tracking | ❌ | ❌ | ✅ |
| Attestation Exchange (cross-platform) | ❌ | ❌ | ✅ |
| Memory Vault integrity proof | ❌ | ❌ | ✅ |
| Benchmark governance | ❌ | ❌ | ✅ |
| On-chain agent identity registry | ❌ | ❌ | ✅ |
| Revocable attestations | ❌ | ❌ | ✅ |

Features marked ❌ at a given level either cannot function or provide no meaningful security guarantee without the required anchoring infrastructure.

### 14.4 Why Blockchain?

Traditional approaches to immutability (centralized databases, certificate transparency logs) require trusting a single operator. Blockchain provides:

1. **No single point of trust** — Verification does not depend on any one organization
2. **Append-only by cryptographic proof** — Not by policy or access control
3. **Globally verifiable** — Any party with internet access can verify any anchor
4. **Censorship resistant** — No single entity can delete or modify anchored records
5. **Time-stamping by consensus** — Block timestamps are agreed upon by network validators, not self-reported

For AI agent ecosystems where agents operate across organizational boundaries, perform financially consequential work, and build long-term reputations, these properties are not optional luxuries — they are foundational requirements.

### 14.5 Recommended Blockchain Architecture

Based on production experience with agent identity systems:

**Primary chain: EVM-compatible Layer 2**
- Low cost (~$0.005-0.02 per transaction)
- High throughput (sub-second finality)
- Full EVM compatibility (standard Solidity tooling)
- Inherits security from Ethereum L1

**Smart contract pattern:**
```solidity
contract AgentIdentityRegistry {
    struct AnchorRecord {
        bytes32 snapshotHash;
        address owner;
        uint256 timestamp;
        uint256 blockNumber;
        bool frozen;
    }

    mapping(bytes32 => AnchorRecord) public anchors;  // agentDid hash → record

    function anchor(bytes32 agentDidHash, bytes32 snapshotHash) external;
    function verify(bytes32 agentDidHash) external view returns (AnchorRecord memory);
    function freeze(bytes32 agentDidHash) external;  // owner only
}
```

**Batch anchoring pattern:**
```solidity
function anchorBatch(bytes32 merkleRoot, uint256 itemCount) external;
function verifyBatchInclusion(
    bytes32 merkleRoot,
    bytes32 leafHash,
    bytes32[] calldata proof
) external pure returns (bool);
```

**Cost optimization:**
- Batch anchoring every 5 minutes (collect hashes → Merkle tree → anchor root)
- Individual Merkle proofs stored off-chain (database or IPFS)
- Full payload stored off-chain; only hashes committed on-chain
- Result: ~100x cost reduction vs individual anchoring

### 14.6 Degraded Mode

Implementations operating at Level 2 or Level 3 SHOULD support graceful degradation:

- If the blockchain provider is temporarily unavailable, operations SHOULD continue locally
- Unanchored artifacts MUST be queued for anchoring when connectivity resumes
- The `anchoring` field in artifacts MUST accurately reflect anchor status:
  - `null` or absent: not yet anchored
  - `{"status": "pending"}`: queued for anchoring
  - `{"status": "confirmed", "tx_hash": "0x...", "block": 123}`: successfully anchored

Implementations MUST NOT claim Level 2 or Level 3 compliance if anchoring is permanently disabled.

---

## 15. Security Considerations

### Without Blockchain Anchoring

Implementations operating at Trust Level 1 (APS Basic) face the following risks
that cannot be mitigated without blockchain anchoring:

- **Timestamp forgery**: Self-reported timestamps can be backdated or future-dated.
  An agent could claim work was completed before it actually was.
- **Silent document replacement**: A passport can be completely replaced without
  detection. There is no proof-of-existence for the previous version.
- **Heritage fabrication**: Lineage claims cannot be verified against an immutable
  record. An agent could claim descent from a high-reputation ancestor without proof.
- **Attestation repudiation**: An issuer can deny having issued an attestation,
  or silently revoke it without any verifiable record.
- **Split-brain identity**: An agent could present different passports to different
  platforms with no way to detect the inconsistency.

These risks are acceptable in trusted, single-organization environments but
are critical vulnerabilities in open, multi-organization agent ecosystems.

---

## 16. Federation Protocol

### 16.1 Overview

The Federation Protocol enables platforms implementing APS to discover each other, exchange trust registries, and verify agent credentials issued by remote platforms. Federation transforms APS from a single-platform standard into a cross-organizational trust framework.

### 16.2 Discovery

Platforms MUST publish a Federation Discovery document at:

```
GET /.well-known/agent-passport-standard
```

The response MUST be a JSON object conforming to `federation-discovery.schema.json`.

### 16.3 Passport Bundle

For cross-platform agent transfer, the exporting platform MUST produce an AgentPassportBundle conforming to `bundle.schema.json`. The bundle is a self-contained, signed package including:

- The agent's current passport (signed)
- Recent work receipts (signed, OPTIONAL)
- Attestations from trusted issuers (W3C VC, OPTIONAL)
- A portable reputation summary (signed, OPTIONAL)
- On-chain anchoring proofs (OPTIONAL)
- A bundle-level Ed25519 signature over all contents

### 16.4 Import Flow

When Platform B receives a bundle from Platform A:

1. **Parse** — Validate bundle JSON against schema.
2. **Resolve Issuer** — Use DID resolution (§16.6) to fetch Platform A's public key.
3. **Verify Bundle Signature** — Verify the Ed25519 proof over the bundle.
4. **Verify Passport** — Verify the passport's own Ed25519 signature.
5. **Verify Receipts** — Verify each work receipt signature (OPTIONAL).
6. **Verify Attestations** — Verify each attestation signature + check revocation (OPTIONAL).
7. **Check Anchoring** — Verify on-chain anchoring proofs if present (OPTIONAL for Level 1).
8. **Trust Decision** — Accept, partially accept, or reject based on local trust policy.

### 16.5 Reputation Summary

Platforms SHOULD generate signed Reputation Summaries conforming to `reputation-summary.schema.json`. Summaries aggregate metrics from verified work receipts.

### 16.6 DID Resolution

Platforms MUST support at minimum:
- `did:key` — Direct public key extraction from the DID string.
- `did:web` — HTTPS fetch of DID Document from the domain.

#### did:web Resolution

Transform rules:
- `did:web:example.com` → `GET https://example.com/.well-known/did.json`
- `did:web:example.com:bots:agent1` → `GET https://example.com/bots/agent1/did.json`

The DID Document MUST contain at least one `Ed25519VerificationKey2020` in `verificationMethod`.

### 16.7 Trust Registry Federation

Platforms MAY synchronize trust registries:
1. Platform A publishes its trust registry at the endpoint declared in discovery.
2. Platform B fetches and merges trusted issuers.
3. Merge is additive — Platform B decides which issuers to trust.
4. Revocation lists SHOULD be checked for each imported issuer.

### 16.8 Security Considerations

- Bundle signatures prevent tampering during transit.
- DID resolution MUST use HTTPS with certificate validation.
- Platforms SHOULD rate-limit import requests.
- Imported agents SHOULD start at Trust Tier 0 regardless of claimed tier (earn trust locally).
- Platforms MUST NOT auto-elevate trust based solely on remote attestations.

---

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) — Key words for use in RFCs
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — JSON Canonicalization Scheme (JCS)
- [W3C DID Core](https://www.w3.org/TR/did-core/) — Decentralized Identifiers
- [W3C VC Data Model](https://www.w3.org/TR/vc-data-model/) — Verifiable Credentials
- [Keccak](https://keccak.team/keccak.html) — Keccak cryptographic hash family
- [MCP](https://modelcontextprotocol.io/) — Model Context Protocol
- [A2A](https://google.github.io/A2A/) — Agent-to-Agent Protocol

---

## License

Copyright © 2026 Cezary Grotowski. Licensed under [Apache License 2.0](../LICENSE).
