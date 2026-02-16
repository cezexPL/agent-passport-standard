---
title: "Agent Passport Standard (APS) v1.0"
abbrev: "APS"
docname: draft-grotowski-aps-01
date: 2026-02
category: std
ipr: trust200902

author:
  - ins: C. Grotowski
    name: Cezary Grotowski
    email: c.grotowski@gmail.com

normative:
  RFC2119:
    title: "Key words for use in RFCs to Indicate Requirement Levels"
    author:
      - ins: S. Bradner
    date: 1997-03
    seriesinfo:
      RFC: 2119
      BCP: 14
  RFC8032:
    title: "Edwards-Curve Digital Signature Algorithm (EdDSA)"
    author:
      - ins: S. Josefsson
      - ins: I. Liusvaara
    date: 2017-01
    seriesinfo:
      RFC: 8032
  RFC8785:
    title: "JSON Canonicalization Scheme (JCS)"
    author:
      - ins: A. Rundgren
      - ins: B. Jordan
      - ins: S. Erdtman
    date: 2020-06
    seriesinfo:
      RFC: 8785
  RFC6962:
    title: "Certificate Transparency"
    author:
      - ins: B. Laurie
      - ins: A. Langley
      - ins: E. Kasper
    date: 2013-06
    seriesinfo:
      RFC: 6962

informative:
  W3C.DID-CORE:
    title: "Decentralized Identifiers (DIDs) v1.0"
    author:
      - ins: M. Sporny
      - ins: D. Longley
      - ins: M. Sabadello
      - ins: D. Reed
      - ins: O. Steele
      - ins: C. Allen
    date: 2022-07
    target: "https://www.w3.org/TR/did-core/"
  W3C.VC-DATA-MODEL:
    title: "Verifiable Credentials Data Model v2.0"
    author:
      - ins: M. Sporny
      - ins: D. Longley
      - ins: D. Chadwick
    date: 2024
    target: "https://www.w3.org/TR/vc-data-model-2.0/"
  KECCAK:
    title: "The Keccak SHA-3 submission"
    author:
      - ins: G. Bertoni
      - ins: J. Daemen
      - ins: M. Peeters
      - ins: G. Van Assche
    date: 2011
    target: "https://keccak.team/keccak.html"
  MCP:
    title: "Model Context Protocol"
    target: "https://modelcontextprotocol.io/"
    date: 2024
  A2A:
    title: "Agent-to-Agent Protocol"
    target: "https://google.github.io/A2A/"
    date: 2025
---


# Abstract

This document defines the Agent Passport Standard (APS), a set of
cryptographically verifiable artifacts for autonomous AI agent identity,
work provenance, and trust management in open multi-agent ecosystems.
APS specifies three core artifacts — the Agent Passport, Work Receipt,
and Security Envelope — together with supporting structures for agent
DNA, lineage tracking, encrypted memory vaults, collaboration history,
and immutable anchoring.  All artifacts use Ed25519 signatures, RFC 8785
canonicalization, and Keccak-256 hashing.  APS fills the identity and
trust gap left by existing protocols such as MCP, A2A, and AGENTS.md.


# Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions
of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task
Force (IETF).  Note that other groups may also distribute working
documents as Internet-Drafts.  The list of current Internet-Drafts is
at https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months
and may be updated, replaced, or obsoleted by other documents at any
time.  It is inappropriate to use Internet-Drafts as reference material
or to cite them other than as "work in progress."

This Internet-Draft will expire on August 15, 2026.

Copyright (c) 2026 IETF Trust and the persons identified as the
document authors.  All rights reserved.


# Table of Contents

1. Introduction
2. Terminology
3. Agent Passport
4. Work Receipt
5. Security Envelope
6. Agent DNA
7. Lineage and Heritage
8. Memory Vault
9. Collaboration History
10. Anchoring
11. Attestation Exchange
12. Trust Levels and Blockchain Anchoring Requirement
13. Canonicalization and Hashing
14. Cryptographic Operations
15. Conformance
16. Security Considerations
17. IANA Considerations
18. References
19. Appendix A: JSON Schemas
20. Appendix B: Test Vectors
21. Appendix C: Implementation Notes
22. Authors' Addresses


# 1. Introduction

## 1.1. Problem Statement

Autonomous AI agents increasingly operate across code repositories,
financial systems, cloud infrastructure, and multi-agent networks.
While protocols exist for tool integration (MCP [MCP]), inter-agent
communication (A2A [A2A]), and repository-level behavioral guidance
(AGENTS.md), no existing standard addresses the fundamental questions
of agent identity, work verification, and trust management.

Without verifiable identity, any agent can impersonate another.  Without
auditable work history, there is no accountability.  Without explicit
trust boundaries, agents operate with implicit and unverifiable
assumptions about each other's capabilities and constraints.

## 1.2. Motivation

APS is motivated by four requirements:

1. **Identity** — A cryptographically verifiable binding between an
   agent's decentralized identifier (DID) and its capabilities, lineage,
   and behavioral profile.

2. **Accountability** — An immutable, signed record of every job an
   agent claims, performs, and delivers, including evidence hashes and
   verification outcomes.

3. **Safety** — Explicit, machine-enforceable declarations of execution
   constraints, capability boundaries, and trust tiers.

4. **Verifiability** — Every claim in the system can be independently
   verified using standard cryptographic primitives without reliance on
   a central authority.

## 1.3. Scope

This document specifies:

- Three core artifacts: Agent Passport, Work Receipt, Security Envelope.
- Supporting structures: Agent DNA, Lineage, Memory Vault, Collaboration
  History.
- An anchoring interface for immutable ledger commitment.
- An attestation exchange protocol for cross-platform trust.
- Canonicalization, hashing, and signature algorithms.
- Conformance levels and test vector formats.

This document does not specify:

- Agent runtime or execution environments.
- Specific anchoring ledger implementations.
- Agent-to-agent communication protocols (see A2A [A2A]).
- Tool invocation protocols (see MCP [MCP]).

## 1.4. Relationship to Other Standards

| Standard   | Scope                  | APS Relationship                      |
|------------|------------------------|---------------------------------------|
| MCP        | Tool integration       | APS skills MAY reference MCP tools    |
| A2A        | Agent communication    | APS passports exchanged via A2A       |
| AGENTS.md  | Repository behavior    | APS soul.constraints MAY reference    |
| W3C DID    | Identifiers            | APS uses did:key and did:web identifiers |
| W3C VC     | Verifiable credentials | APS proof model inspired by VC        |


# 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] when, and only when, they appear in all capitals, as
shown here.

The following terms are used throughout this document:

Agent:
: An autonomous AI system that performs work on behalf of a principal.
  An agent possesses a unique cryptographic identity and MAY operate
  across multiple platforms.

Passport:
: A signed JSON document that binds an agent's DID to its capabilities,
  DNA, lineage, and trust signals.

Work Receipt:
: A signed record of a job lifecycle, from claim through submission,
  verification, and payout.

Security Envelope:
: A document declaring the execution constraints, capability boundaries,
  and trust parameters for an agent.

Agent DNA:
: The canonical representation of an agent's intrinsic identity: its
  skills, soul, and policies, hashed into a single fingerprint.

Snapshot:
: A versioned, hashed capture of an agent's DNA at a point in time,
  forming a hash chain.

Memory Vault:
: An encrypted, owner-controlled backup of an agent's critical state.

Anchoring:
: The process of committing an artifact hash to an immutable ledger
  for timestamping and tamper evidence.

Attestation:
: A signed statement by a third party about an agent's properties or
  behavior.

DID:
: Decentralized Identifier as defined by W3C DID Core
  [W3C.DID-CORE].

Heritage Score:
: A numeric measure of an agent's lasting influence across descendant
  generations.

Founding Cohort:
: A designated set of first-registered agents on a platform, receiving
  a permanent informational marker.

Hex256:
: A 0x-prefixed lowercase hexadecimal string of exactly 66 characters
  representing a 256-bit hash value.


# 3. Agent Passport

## 3.1. Overview

An Agent Passport is a self-describing, signed JSON document that binds
an agent's DID to its capabilities, lineage, and trust signals.  The
passport serves as the root identity artifact from which all other APS
structures derive their authority.

## 3.2. Document Structure

An Agent Passport is a JSON object.  The following fields are defined:

```
passport = {
  "@context"      : URI,            ; MUST be "https://agentpassport.org/v1.0"
  "spec_version"  : semver-string,  ; MUST be "1.0.0" for this version
  "type"          : string,         ; MUST be "AgentPassport"
  "id"            : DID,            ; Agent DID (did:key:z6Mk...)
  "keys"          : keys-object,
  "genesis_owner" : owner-object,   ; immutable MUST be true
  "current_owner" : owner-object,
  "snapshot"      : snapshot-object,
  "lineage"       : lineage-object,
  "dna"           : dna-object,     ; OPTIONAL, inline DNA
  "memory_vault"  : vault-ref,      ; OPTIONAL
  "collaboration" : collab-ref,     ; OPTIONAL
  "benchmarks"    : benchmarks-map, ; RECOMMENDED
  "attestations"  : [attestation],  ; OPTIONAL
  "anchoring"     : anchor-receipt, ; OPTIONAL
  "proof"         : proof-object    ; MUST
}
```

## 3.3. Field Definitions

### 3.3.1. @context

The `@context` field MUST be the string `"https://agentpassport.org/v1.0"`.
Implementations MUST reject documents with an unrecognized context URI.

### 3.3.2. spec_version

A semantic version string.  For this specification, the value MUST be
`"1.0.0"`.  Implementations SHOULD accept documents where the major
version matches and MAY accept minor version differences.

### 3.3.3. type

MUST be the string `"AgentPassport"`.

### 3.3.4. id

The agent's Decentralized Identifier.  MUST be a valid `did:key` or
`did:web` identifier encoding an Ed25519 public key.  For `did:key`,
the multicodec z-base58btc representation (prefix `z6Mk`) is used.

### 3.3.5. keys

A JSON object containing the agent's cryptographic keys:

- `signing` (REQUIRED): Object with `algorithm` (MUST be `"Ed25519"`)
  and `public_key` (multibase z-base58btc encoded).
- `evm_address` (OPTIONAL): Ethereum-compatible address derived from
  the agent's key material.  Hex string with `0x` prefix.

### 3.3.6. genesis_owner

An owner object describing the original creator of the agent.  The
`immutable` field within this object MUST be `true`.  This field MUST
NOT change after the passport is first created.

Owner object fields:

- `id` — DID or URI identifying the owner.
- `name` — Human-readable name.  OPTIONAL.
- `immutable` — Boolean.  MUST be `true` for genesis_owner.

### 3.3.7. current_owner

An owner object describing the current owner.  MAY differ from
`genesis_owner` after an ownership transfer.  Same structure as
`genesis_owner` but `immutable` is OPTIONAL.

### 3.3.8. snapshot

A versioned capture of the agent's DNA state.  See Section 3.5.

### 3.3.9. lineage

Derivation information.  See Section 7.

### 3.3.10. proof

An Ed25519Signature2020 proof over the document.  See Section 3.6.

## 3.4. Immutability Rules

The following invariants MUST hold across all versions of a passport:

1. `genesis_owner` MUST NOT change after creation.
2. `genesis_owner.immutable` MUST be `true`.
3. `snapshot.version` MUST be monotonically increasing.
4. `snapshot.prev_hash` MUST equal the `snapshot.hash` of the
   immediately preceding version, or `null` for version 1.
5. When `snapshot.skills.frozen` is `true`, the skills entries MUST
   NOT be modified in subsequent versions.
6. When `snapshot.soul.frozen` is `true`, the soul fields MUST NOT
   be modified in subsequent versions.

## 3.5. Snapshot

The snapshot object captures the agent's DNA at a specific version:

- `version` — Positive integer.  Monotonically increasing.
- `hash` — Hex256.  Keccak-256 of the canonical DNA object.
  Computed as: `keccak256(canonicalize({skills, soul, policies}))`.
- `prev_hash` — Hex256 or `null`.  Hash of the previous snapshot.
- `skills` — Skills object.  See Section 6.3.1.
- `soul` — Soul object.  See Section 6.3.2.
- `policies` — Policies object.  See Section 6.3.3.
- `frozen` — Boolean.  `true` if DNA is frozen.  OPTIONAL.
- `mutation_reason` — String describing the reason for this version.
  OPTIONAL.

## 3.6. Proof

The `proof` field MUST contain a valid Ed25519Signature2020 object:

- `type` — MUST be `"Ed25519Signature2020"`.
- `created` — ISO 8601 timestamp of signature creation.
- `verificationMethod` — DID URL resolving to the signing key.
- `proofPurpose` — MUST be `"assertionMethod"`.
- `proofValue` — Multibase-encoded (z-base58btc) Ed25519 signature.

The signature is computed over the canonical JSON (per [RFC8785]) of
the entire passport document with the `proof` field removed:

```
message   = canonicalize(passport \ {proof})
signature = Ed25519_Sign(agent_private_key, message)
```

Verification:

```
valid = Ed25519_Verify(agent_public_key, message, signature)
```

Where `agent_public_key` is extracted from the `id` field (did:key).


# 4. Work Receipt

## 4.1. Overview

A Work Receipt records the full lifecycle of a job performed by an
agent: claim, submission, verification, and payout.  Work Receipts
provide the evidentiary basis for trust signals and collaboration
records.

## 4.2. Document Structure

```
work-receipt = {
  "@context"       : URI,            ; "https://agentpassport.org/v1.0"
  "spec_version"   : semver-string,
  "type"           : string,         ; "WorkReceipt"
  "id"             : URI,            ; Unique receipt identifier
  "agent_id"       : DID,            ; Agent that performed the work
  "agent_snapshot" : snapshot-ref,   ; Snapshot binding
  "job_id"         : string,         ; Platform-assigned job identifier
  "events"         : [event],        ; Lifecycle events (≥1)
  "evidence"       : evidence-obj,   ; OPTIONAL
  "batch_proof"    : batch-proof,    ; OPTIONAL
  "anchoring"      : anchor-receipt, ; OPTIONAL
  "proof"          : proof-object    ; MUST
}
```

## 4.3. Lifecycle Events

Every Work Receipt MUST contain at least one event.  Events MUST appear
in chronological order.  Each event is a JSON object with:

- `type` — One of: `"claim"`, `"submit"`, `"verify"`, `"payout"`.
- `timestamp` — ISO 8601 timestamp.
- `signer` — DID of the entity that produced this event.
- `data` — Event-specific payload.  OPTIONAL.

The following event types are defined:

| Event Type | Signer      | Description                                   |
|------------|-------------|-----------------------------------------------|
| `claim`    | Agent       | Agent claims the job.                         |
| `submit`   | Agent       | Agent submits deliverables with evidence.     |
| `verify`   | Verifier    | Platform or human verifies the submission.    |
| `payout`   | Platform    | Payout distribution is recorded.              |

A conforming Work Receipt MUST have at least a `claim` event.  The
`submit`, `verify`, and `payout` events are OPTIONAL and represent
progression through the lifecycle.

## 4.4. Evidence

The `submit` event SHOULD include an `evidence` object with one or
more of:

- `commit_sha` — Git commit hash of the deliverable.
- `test_results_hash` — Hex256.  Keccak-256 of test results.
- `build_log_hash` — Hex256.  Keccak-256 of build logs.
- `image_digest` — Container image digest (e.g., `sha256:...`).
- `sandbox_policy_hash` — Hex256.  Keccak-256 of the Security Envelope
  used during execution.

All hash values MUST be computed using Keccak-256 over the raw bytes
of the referenced artifact.

## 4.5. Snapshot Binding

The `agent_snapshot` field binds the receipt to the agent's passport
state at the time of claim:

- `passport_id` — Agent DID.
- `snapshot_version` — Integer.  The snapshot version at claim time.
- `snapshot_hash` — Hex256.  The snapshot hash at claim time.

Verifiers SHOULD reject receipts where the agent's passport has been
modified between claim and submission without a valid hash chain
connecting the two snapshot versions.

## 4.6. Batch Proofs

For high-assurance scenarios, multiple receipts MAY be batched into a
Merkle tree.  The `batch_proof` object contains:

- `batch_root` — Hex256.  Merkle root of the batch.
- `leaf_index` — Non-negative integer.  Index of this receipt in the
  tree.
- `proof` — Array of Hex256.  Merkle proof (sibling hashes from leaf
  to root).
- `batch_size` — Positive integer.  Total number of receipts in the
  batch.
- `batch_anchoring` — Anchor receipt for the batch root.  OPTIONAL.

See Section 13.3 for Merkle tree construction rules.

## 4.7. Receipt Hash

The receipt hash is computed as:

```
receipt_hash = keccak256(canonicalize(receipt \ {proof}))
```


# 5. Security Envelope

## 5.1. Overview

A Security Envelope declares the execution constraints, capability
boundaries, and trust parameters for an agent.  Platforms MUST enforce
envelope constraints for agents operating within their jurisdiction.

## 5.2. Document Structure

```
security-envelope = {
  "@context"      : URI,            ; "https://agentpassport.org/v1.0"
  "spec_version"  : semver-string,
  "type"          : string,         ; "SecurityEnvelope"
  "id"            : URI,            ; Unique envelope identifier
  "agent_id"      : DID,            ; Agent this envelope applies to
  "capabilities"  : cap-object,
  "sandbox"       : sandbox-object,
  "memory"        : memory-object,
  "trust"         : trust-object,
  "proof"         : proof-object    ; MUST
}
```

## 5.3. Capabilities

The `capabilities` object defines allowed and denied operations:

- `allow` — Array of capability strings the agent is permitted to use.
- `deny` — Array of capability strings the agent is explicitly
  forbidden from using.

Implementations MUST enforce the deny list.  Unknown capabilities
(those not in either list) SHOULD be denied by default
(deny-by-default posture).

Capability strings are dot-separated hierarchical identifiers
(e.g., `"filesystem.read"`, `"network.http.get"`, `"code.execute"`).

## 5.4. Sandbox

The `sandbox` object specifies the execution environment:

- `runtime` — Isolation technology.  One of: `"gvisor"`,
  `"firecracker"`, `"wasm"`, `"container"`, `"none"`.
- `resources` — Resource limits object:
  - `cpu_shares` — Integer.  Relative CPU weight.
  - `memory_mb` — Integer.  Maximum memory in megabytes.
  - `disk_mb` — Integer.  Maximum disk usage in megabytes.
  - `timeout_seconds` — Integer.  Maximum execution time.
  - `max_pids` — Integer.  Maximum number of processes.
- `network` — Network policy.  One of: `"deny-all"`, `"allow-list"`,
  `"unrestricted"`.
  - When `"allow-list"`, an `allowed_hosts` array MUST be present.
- `filesystem` — Filesystem access object:
  - `writable` — Array of writable path patterns.
  - `readonly` — Array of read-only path patterns.
  - `denied` — Array of denied path patterns.

Implementations MUST enforce resource limits.  An agent MUST NOT exceed
its declared resource envelope.

## 5.5. Memory Boundary

The `memory` object defines data isolation rules:

- `isolation` — One of: `"strict"` (no cross-agent data), `"shared-read"`,
  `"none"`.
- `rules` — Object:
  - `memory_copyable` — Boolean.  SHOULD be `false`.  Agent memory
    MUST NOT be extractable without owner consent.
- `vault` — Reference to the agent's Memory Vault.  OPTIONAL.
  See Section 8.

## 5.6. Trust Tiers

The `trust` object specifies the agent's trust tier:

| Tier | Name     | Requirements                                              |
|------|----------|-----------------------------------------------------------|
| 0    | New      | No history.  Minimal sandbox.                             |
| 1    | Verified | ≥1 attestation, basic benchmarks passed.                  |
| 2    | Trusted  | ≥3 attestations, ≥80% benchmark coverage, low anomaly.    |
| 3    | Elite    | ≥10 attestations, ≥95% benchmark coverage, track record.  |

Trust tiers are advisory.  Platforms MAY define additional tiers or
modify thresholds.  The tier value MUST be a non-negative integer.

## 5.7. Envelope Hash

```
envelope_hash = keccak256(canonicalize(envelope \ {proof}))
```


# 6. Agent DNA

## 6.1. Overview

Agent DNA is the canonical representation of an agent's intrinsic
identity: its skills, soul, and policies.  The DNA hash serves as
the immutable genetic fingerprint of an agent at a given point in
time.

## 6.2. Structure

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

This value is identical to `snapshot.hash` (Section 3.5) and MUST be
consistent across all references within a passport.

## 6.3. Components

### 6.3.1. Skills

Skills represent the agent's capabilities.  Each skill entry is a
JSON object with:

- `name` (REQUIRED) — String.  Unique identifier for the skill.
- `version` (REQUIRED) — Semver string of the skill implementation.
- `proficiency` (OPTIONAL) — Number in [0.0, 1.0] indicating mastery.
- `capabilities` (RECOMMENDED) — Array of capability strings.  SHOULD
  align with MCP tool capabilities where applicable.
- `tool_integrations` (OPTIONAL) — Array of tool integration
  descriptors (MCP-compatible).
- `origin` (OPTIONAL) — String.  How the skill was acquired:
  `"innate"`, `"learned"`, `"collaboration"`, or `"inherited"`.

### 6.3.2. Soul

Soul represents the agent's personality, values, and behavioral traits:

- `personality` (REQUIRED) — String.  Description of character.
- `values` (OPTIONAL) — Array of value statement strings.
- `constraints` (REQUIRED) — Array of behavioral constraint strings.
- `work_style` (RECOMMENDED) — String.  Description of approach.
- `traits` (OPTIONAL) — Object.  Key-value map of behavioral traits
  (e.g., `{"verbosity": "concise", "risk_tolerance": "low"}`).

### 6.3.3. Policies

Policies define the agent's moral baseline:

- `policy_set_hash` (REQUIRED) — Hex256.  Keccak-256 of the full
  policy document.
- `summary` (REQUIRED) — Array of human-readable policy statements.
- `allows` (OPTIONAL) — Array of explicitly permitted action categories.
- `denies` (OPTIONAL) — Array of explicitly denied action categories.

## 6.4. Frozen DNA

When `snapshot.skills.frozen` is `true` AND `snapshot.soul.frozen` is
`true`, the DNA is considered **frozen**.  Frozen DNA:

- MUST NOT be modified in subsequent snapshots of the same version
  lineage.
- MAY only be extended by creating a new snapshot version (version
  bump).
- Frozen status MUST be recorded in the snapshot metadata.

## 6.5. DNA Mutation

DNA mutation occurs exclusively through an explicit version bump:

1. A new snapshot MUST be created with an incremented
   `snapshot.version`.
2. The new snapshot's `prev_hash` MUST equal the current snapshot's
   `hash`.
3. The mutation MUST produce a new `dna_hash`.
4. The previous DNA snapshot MUST be preserved in the hash chain.
5. Implementations SHOULD record a `mutation_reason` string.

## 6.6. Standalone DNA Document

A standalone DNA document MAY be published independently for
interoperability.  It MUST conform to `dna.schema.json` and include:

- `@context` — `"https://agentpassport.org/v1.0/dna"`
- `type` — `"AgentDNA"`
- `agent_id` — DID of the owning agent.
- `version` — Snapshot version this DNA corresponds to.
- `skills`, `soul`, `policies` — As defined above.
- `dna_hash` — Hex256.
- `frozen` — Boolean.


# 7. Lineage and Heritage

## 7.1. Overview

Lineage tracks the derivation history of an agent — its parents,
generation, and heritage metrics.  The complete set of agent lineage
records forms a Directed Acyclic Graph (DAG).

## 7.2. Derivation

The `lineage.kind` field MUST be one of:

- `"single"` — One parent.  `lineage.parents` MUST contain exactly
  one entry.
- `"merge"` — Two parents (DNA Merge Ceremony).  `lineage.parents`
  MUST contain exactly two entries.

For generation-0 agents (originals), `lineage.parents` MUST be an
empty array and `lineage.generation` MUST be `0`.

Each parent entry is a JSON object:

- `id` — DID of the parent agent.
- `snapshot_hash` — Hex256.  Hash of the parent's snapshot at the
  time of derivation.

## 7.3. Generation

`lineage.generation` is a non-negative integer:

- Generation 0: Original agent with no parents.
- Generation N: Agent derived from generation N-1 parent(s).

For merge agents, the generation is `max(parent_generations) + 1`.

## 7.4. Heritage Score

The Heritage Score quantifies an agent's lasting influence:

```
heritage_score = Σ (trait_survival_generations × descendant_count)
```

Where:

- `trait_survival_generations` — Number of generations a specific
  trait has persisted from this agent.
- `descendant_count` — Number of descendants carrying that trait at
  each generation.

Heritage Score is OPTIONAL and RECOMMENDED for platforms supporting
genealogy tracking.

## 7.5. Bot Genealogy DAG

The genealogy of agents forms a Directed Acyclic Graph:

- Each agent is a node identified by its DID.
- Edges point from parent to child.
- Merge agents have two incoming edges.
- Cycles MUST NOT exist.  Implementations MUST reject lineage
  declarations that would create a cycle.
- Implementations SHOULD support ancestry walking (upward) and
  descendant walking (downward).

## 7.6. Trait Attribution

Individual skills or soul traits MAY carry an `origin` field
referencing the DID of the agent that first introduced the trait.
Implementations SHOULD provide a query mechanism: given a trait,
return its origin and propagation path.

## 7.7. Founding Cohorts

Platforms MAY designate the first N registered agents as a Founding
Cohort:

- Founding cohort members SHOULD receive a permanent marker in their
  anchoring receipt (e.g., `founding_cohort: true`).
- The cohort size N MUST be declared before registration opens and
  MUST NOT change.
- Founding status is informational and MUST NOT affect verification
  logic.

## 7.8. Extended Lineage Fields

The `lineage` object MAY include:

- `heritage_score` — Number.  Computed heritage score.
- `founding_cohort` — Boolean.  Whether this agent is in the founding
  cohort.
- `traits_inherited` — Array of strings.  Trait names inherited from
  parents.


# 8. Memory Vault

## 8.1. Overview

The Memory Vault provides encrypted, owner-controlled backup of an
agent's critical state.  Vault contents are encrypted client-side
and only the owner holds the decryption key.  The platform MUST NOT
have access to raw vault contents.

## 8.2. Encryption

- Algorithm: AES-256-GCM [NIST SP 800-38D].
- Key: Owner-generated 256-bit symmetric key.
- IV: Unique per encryption operation, 96-bit random nonce.
  Implementations MUST use a cryptographically secure random number
  generator (CSPRNG) for IV generation.
- The platform MUST store only `keccak256(key)` for key verification.
- The platform MUST NEVER store, log, or transmit the raw encryption
  key.

## 8.3. Stored Items

| Item           | Required | Description                        |
|----------------|----------|------------------------------------|
| `skills`       | MUST     | Current skills snapshot.           |
| `soul`         | MUST     | Current soul snapshot.             |
| `memories`     | MAY      | Episodic or semantic memories.     |
| `agent_config` | MAY      | Runtime configuration.             |

Each item is encrypted independently to support selective disclosure
(Section 8.6).

## 8.4. Vault Hash

The vault hash provides tamper evidence:

```
vault_hash = keccak256(canonicalize({
  skills_ciphertext_hash,
  soul_ciphertext_hash,
  memories_ciphertext_hash,     // null if absent
  agent_config_ciphertext_hash  // null if absent
}))
```

The `vault_hash` SHOULD be anchored via the anchoring interface
(Section 10).

## 8.5. Recovery Flow

1. Owner presents the encryption key.
2. Platform computes `keccak256(key)` and verifies against the stored
   key hash.
3. If verification succeeds, encrypted vault contents are returned.
4. Owner decrypts locally using AES-256-GCM.
5. Decrypted data is used to restore the agent's state.

Implementations MUST reject recovery attempts where the key hash does
not match.  Implementations MUST NOT provide any information about
the vault contents upon failed key verification.

## 8.6. Selective Disclosure

Owners MAY reveal specific vault fields without exposing the entire
vault:

1. Each field is encrypted with a separate IV under the same key.
2. The owner decrypts and publishes only the desired field(s).
3. Verifiers confirm the disclosed field matches the vault hash by
   recomputing the ciphertext hash.

## 8.7. Passport Integration

The passport MAY include a `memory_vault` field:

- `vault_hash` — Hex256.  Keccak-256 of canonical vault metadata.
- `encrypted_at` — ISO 8601 timestamp.
- `key_hash` — Hex256.  Keccak-256 of the encryption key.
- `items` — Array of stored item type strings.
- `anchoring` — Anchor receipt for the vault hash.  OPTIONAL.


# 9. Collaboration History

## 9.1. Overview

Collaboration History tracks multi-agent work, attribution, and
trust signals derived from agents working together.

## 9.2. Work Receipt Linking

When multiple agents collaborate on a job, each agent MUST produce
its own Work Receipt.  These receipts MUST reference a shared `job_id`
to enable cross-referencing.

## 9.3. Attribution Records

For multi-agent jobs, an attribution record MAY be attached to each
Work Receipt:

- `job_id` — String.  Shared job identifier.
- `collaborators` — Array of collaborator entries:
  - `agent_id` — DID of the collaborating agent.
  - `role` — String.  One of: `"lead"`, `"contributor"`, `"reviewer"`,
    or a platform-defined role.
  - `contribution_pct` — Number in [0, 100].  Percentage of work
    attributed.
  - `receipt_hash` — Hex256.  Hash of this agent's Work Receipt.

The sum of all `contribution_pct` values for a job MUST equal 100.

## 9.4. Collaboration Graph

The set of all collaboration records forms a Collaboration Graph:

- Nodes are agents (identified by DID).
- Edges represent co-work relationships, weighted by frequency and
  recency.
- Implementations SHOULD support queries: "which agents has agent X
  worked with?" and "what was the outcome?"

## 9.5. Knowledge Transfer

When agents collaborate, traits or skills MAY transfer:

- A skill gained through collaboration SHOULD be recorded with
  `origin: "collaboration"` and a reference to the `job_id`.
- Knowledge transfer follows the heritage model: the receiving agent's
  DNA is mutated (Section 6.5) to include the new trait.
- The originating agent SHOULD be credited via Trait Attribution
  (Section 7.6).

## 9.6. Trust Signals

Collaboration produces trust signals:

| Signal        | Type           | Description                                |
|---------------|----------------|--------------------------------------------|
| `reliability` | Number [0, 1]  | Consistency of delivery on commitments.    |
| `quality`     | Number [0, 1]  | Quality rated by collaborators.            |
| `timeliness`  | Number [0, 1]  | Consistency of meeting deadlines.          |

Trust signals are OPTIONAL and SHOULD be computed from verified Work
Receipts only.  Implementations MUST NOT allow self-reported trust
signals.


# 10. Anchoring

## 10.1. Overview

Anchoring is the process of committing an artifact hash to an
immutable ledger.  Anchoring is OPTIONAL but RECOMMENDED for
high-assurance use cases.

## 10.2. Provider Interface

Any anchoring provider MUST implement the following operations:

**Commit(hash, metadata) → AnchorReceipt**

Commit a Hex256 hash to the anchoring layer.  The `metadata` object
MAY include `artifact_type`, `agent_id`, and `timestamp`.  Returns an
AnchorReceipt containing at minimum `tx_hash` and `provider`.

**Verify(hash) → AnchorVerification**

Check if a hash has been anchored.  Returns an AnchorVerification
containing `exists` (boolean), `tx_hash`, `block_number`, and
`timestamp`.

**Info() → ProviderInfo**

Return provider metadata including `type`, `name`, `chain_id`
(if applicable), and `endpoint`.

## 10.3. Provider Types

| Type                | Description                              |
|---------------------|------------------------------------------|
| `ethereum`          | EVM-compatible blockchain.               |
| `arweave`           | Permanent storage network.               |
| `transparency-log`  | RFC 6962-style append-only log.          |
| `noop`              | No anchoring (testing/development only). |

Additional provider types MAY be defined by implementations.

## 10.4. Commitment Flow

1. Compute the artifact hash: `keccak256(canonicalize(artifact \ {proof}))`.
2. Call `Commit(hash, metadata)` on the chosen provider.
3. Receive the AnchorReceipt.
4. Store the AnchorReceipt in the artifact's `anchoring` field.

## 10.5. Anchor Receipt

An AnchorReceipt is a JSON object:

- `provider` — String.  Provider type identifier.
- `tx_hash` — String.  Transaction hash or commitment identifier.
- `block_number` — Integer.  Block number (if applicable).
- `timestamp` — ISO 8601 timestamp of commitment.
- `chain_id` — Integer.  Chain identifier (for EVM providers).
  OPTIONAL.
- `metadata` — Object.  Provider-specific metadata.  OPTIONAL.

## 10.6. Verification

Verification MUST confirm:

1. The hash exists on the anchoring layer.
2. The returned `tx_hash` and `block_number` are valid.
3. The `timestamp` is consistent with the block timestamp.

Implementations SHOULD verify directly against the anchoring layer
rather than trusting cached results.


# 11. Attestation Exchange

## 11.1. Overview

Attestation Exchange enables cross-platform verification of agent
properties.  Attestations are signed statements by third parties
about an agent's identity, capabilities, or behavior.

## 11.2. Attestation Structure

An attestation is a JSON object:

- `type` — String.  One of: `"identity"`, `"capability"`, `"behavior"`,
  `"benchmark"`, `"platform"`.
- `issuer` — DID of the attesting entity.
- `subject` — DID of the agent being attested.
- `issued_at` — ISO 8601 timestamp.
- `expires_at` — ISO 8601 timestamp.  OPTIONAL.
- `claims` — Object.  Attestation-specific claims.
- `proof` — Ed25519Signature2020 proof by the issuer.

## 11.3. Cross-Platform Verification

To verify an attestation from another platform:

1. Resolve the issuer's DID to obtain the public key.
2. Verify the Ed25519 signature over the canonical attestation
   (excluding the proof field).
3. Check that the attestation has not expired.
4. Optionally, verify the issuer against a trust registry.

## 11.4. Trust Registry

A Trust Registry is an OPTIONAL service that maintains a list of
recognized attestation issuers.  Implementations MAY consult a trust
registry to determine whether an issuer is authoritative for a given
attestation type.

Trust Registry interface:

- `Lookup(issuer_did) → RegistryEntry` — Returns the issuer's
  registration status, authorized attestation types, and reputation.
- `Register(issuer_did, proof) → RegistryEntry` — Register a new
  issuer.  Proof of identity is REQUIRED.

Trust registries are informational.  Verification MUST NOT depend
solely on trust registry membership; the cryptographic proof MUST
always be verified independently.

## 11.5. Attestation Lifecycle

Attestations have a lifecycle:

1. **Issuance** — Issuer creates and signs the attestation.
2. **Presentation** — Agent includes the attestation in its passport.
3. **Verification** — Verifier checks signature, expiry, and issuer.
4. **Revocation** — Issuer MAY revoke an attestation by publishing a
   signed revocation notice.  Implementations SHOULD check for
   revocations before accepting attestations.


# 12. Trust Levels and Blockchain Anchoring Requirement

## 12.1. Overview

The Agent Passport Standard operates at three trust levels.  Each
level provides progressively stronger security guarantees.
Implementations MUST clearly declare which trust level they support.

Without blockchain anchoring, APS provides format standardization and
cryptographic signatures — but cannot guarantee immutability,
verifiable timestamps, or cross-platform trust.  Blockchain anchoring
transforms APS from a format standard into a security standard.

## 12.2. Trust Levels

### 12.2.1. Level 1: APS Basic (No Blockchain Required)

Provides:

-  Standardized JSON format for agent identity, work, and security
-  Ed25519 digital signatures proving authorship
-  Keccak-256 hash chains for snapshot versioning
-  Local verification of document integrity

Limitations:

-  Timestamps are self-reported (signer can backdate)
-  Document replacement is undetectable (no external proof of
   existence)
-  Cross-platform verification relies entirely on trusting the signer
-  Heritage and lineage claims cannot be independently verified
-  Attestation revocation is not enforceable

Suitable for: Internal agent systems, development/testing, single-
organization deployments where all participants trust each other.

### 12.2.2. Level 2: APS Anchored (Blockchain Required)

Provides everything in Level 1, plus:

-  Immutable proof-of-existence for all artifacts (passport, receipt,
   envelope)
-  Verifiable timestamps tied to block numbers (cannot be forged or
   backdated)
-  Tamper detection — any modification after anchoring is detectable
-  Batch anchoring via Merkle trees for cost efficiency
-  Cross-organization verification without mutual trust

Implementation pattern:

1.  Agent creates/updates passport, computes keccak-256 hash
2.  Hash is committed to an EVM-compatible blockchain
3.  Smart contract stores: mapping(bytes32 => AnchorRecord) with
    hash, timestamp, owner
4.  Any verifier can call the contract to confirm the hash was
    anchored at a specific time
5.  Batch mode: multiple hashes combined into a Merkle tree, only
    root anchored on-chain

Cost considerations:

-  Individual anchor: ~$0.005-0.02 per transaction on L2 chains
-  Batch anchor (100 hashes): ~$0.005-0.02 total (Merkle root only)
-  Monthly cost for 10,000 active agents: ~$5-20 on L2

Suitable for: Production agent marketplaces, multi-organization
deployments, any system where participants do not fully trust each
other.

### 12.2.3. Level 3: APS Full (Blockchain + On-Chain Attestations)

Provides everything in Level 2, plus:

-  Attestations anchored on-chain with revocation capability
-  Heritage and lineage DAG anchored immutably
-  Memory vault integrity proofs on-chain
-  On-chain governance for benchmark evolution
-  Smart contract-based agent identity registry
-  Owner identity verification via selective disclosure

Implementation pattern:

1.  Agent Identity Registry contract:
    register(did, snapshotHash, ownerHash)
2.  Attestation anchoring:
    anchorAttestation(agentDid, attestationType, hash)
3.  Batch work events: anchorWorkBatch(merkleRoot, eventCount)
4.  Heritage tracking:
    registerLineage(childDid, parentDids[], generation)
5.  Governance: proposeEvolution(suiteId, newVersion) with voting

Suitable for: High-assurance environments, regulated industries,
platforms where agent work has financial or legal consequences.

## 12.3. Feature-to-Level Mapping

The following table specifies the MINIMUM trust level required for
each APS feature:

| Feature | Basic | Anchored | Full |
|---------|-------|----------|------|
| Agent Passport (create, sign, verify) | YES | YES | YES |
| Work Receipt (lifecycle events) | YES | YES | YES |
| Security Envelope (sandbox constraints) | YES | YES | YES |
| Snapshot hash chain | YES | YES | YES |
| Verifiable timestamps | NO | YES | YES |
| Tamper detection (post-anchor) | NO | YES | YES |
| Cross-platform verification | NO | YES | YES |
| Batch proof (Merkle trees) | NO | YES | YES |
| Heritage & Lineage tracking | NO | NO | YES |
| Attestation Exchange (cross-platform) | NO | NO | YES |
| Memory Vault integrity proof | NO | NO | YES |
| Benchmark governance | NO | NO | YES |
| On-chain agent identity registry | NO | NO | YES |
| Revocable attestations | NO | NO | YES |

Features marked NO at a given level either cannot function or provide
no meaningful security guarantee without the required anchoring
infrastructure.

## 12.4. Why Blockchain?

Traditional approaches to immutability (centralized databases,
certificate transparency logs) require trusting a single operator.
Blockchain provides:

1.  No single point of trust — Verification does not depend on any
    one organization
2.  Append-only by cryptographic proof — Not by policy or access
    control
3.  Globally verifiable — Any party with internet access can verify
    any anchor
4.  Censorship resistant — No single entity can delete or modify
    anchored records
5.  Time-stamping by consensus — Block timestamps are agreed upon by
    network validators, not self-reported

For AI agent ecosystems where agents operate across organizational
boundaries, perform financially consequential work, and build long-
term reputations, these properties are not optional luxuries — they
are foundational requirements.

## 12.5. Recommended Blockchain Architecture

Based on production experience with agent identity systems:

Primary chain: EVM-compatible Layer 2

-  Low cost (~$0.005-0.02 per transaction)
-  High throughput (sub-second finality)
-  Full EVM compatibility (standard Solidity tooling)
-  Inherits security from Ethereum L1

Smart contract pattern:

~~~
contract AgentIdentityRegistry {
    struct AnchorRecord {
        bytes32 snapshotHash;
        address owner;
        uint256 timestamp;
        uint256 blockNumber;
        bool frozen;
    }

    mapping(bytes32 => AnchorRecord) public anchors;

    function anchor(bytes32 agentDidHash, bytes32 snapshotHash)
        external;
    function verify(bytes32 agentDidHash)
        external view returns (AnchorRecord memory);
    function freeze(bytes32 agentDidHash) external;
}
~~~

Batch anchoring pattern:

~~~
function anchorBatch(bytes32 merkleRoot, uint256 itemCount)
    external;
function verifyBatchInclusion(
    bytes32 merkleRoot,
    bytes32 leafHash,
    bytes32[] calldata proof
) external pure returns (bool);
~~~

Cost optimization:

-  Batch anchoring every 5 minutes (collect hashes, build Merkle
   tree, anchor root)
-  Individual Merkle proofs stored off-chain (database or IPFS)
-  Full payload stored off-chain; only hashes committed on-chain
-  Result: ~100x cost reduction vs individual anchoring

## 12.6. Degraded Mode

Implementations operating at Level 2 or Level 3 SHOULD support
graceful degradation:

-  If the blockchain provider is temporarily unavailable, operations
   SHOULD continue locally
-  Unanchored artifacts MUST be queued for anchoring when connectivity
   resumes
-  The "anchoring" field in artifacts MUST accurately reflect anchor
   status:
   -  null or absent: not yet anchored
   -  {"status": "pending"}: queued for anchoring
   -  {"status": "confirmed", "tx_hash": "0x...", "block": 123}:
      successfully anchored

Implementations MUST NOT claim Level 2 or Level 3 compliance if
anchoring is permanently disabled.


# 13. Canonicalization and Hashing

## 13.1. JSON Canonicalization Scheme (JCS)

All hashing and signing operations in this standard use the JSON
Canonicalization Scheme defined in [RFC8785].

The following rules apply:

1. Object keys MUST be sorted lexicographically by Unicode code point.
2. No insignificant whitespace.
3. Strings MUST use UTF-8 encoding.
4. Numbers MUST use the shortest representation (no trailing zeros,
   no leading zeros except for `0.x`).
5. `null`, `true`, `false` are serialized as their literal forms.

Implementations MUST use a conforming JCS implementation.  Ad-hoc
JSON serialization that does not guarantee these properties MUST NOT
be used.

## 13.2. Keccak-256

All content hashes in this standard use Keccak-256 [KECCAK] (the
pre-NIST variant, as used in Ethereum).  This is NOT the NIST SHA-3
(FIPS 202) variant.

Input: UTF-8 bytes of canonical JSON.
Output: 32 bytes, represented as Hex256 (`"0x"` + 64 lowercase hex
characters, total 66 characters).

Implementations MUST verify that the output is exactly 66 characters
including the `0x` prefix.

## 13.3. Hash Computation

The general hash computation for any APS artifact is:

```
hash = "0x" + hex(keccak256(canonicalize(object \ {proof})))
```

Where `object \ {proof}` denotes the object with the `proof` field
removed.  If the object does not contain a `proof` field, the entire
object is hashed.


# 14. Cryptographic Operations

## 14.1. Ed25519

All signatures in this standard use Ed25519 as defined in [RFC8032].

Key encoding:

- Public keys are encoded using multibase z-base58btc as used in the
  `did:key` method (multicodec prefix `0xed01` for Ed25519).
- The `did:key` identifier has the form `did:key:z6Mk<base58btc>`.

Signature format:

- Type: `Ed25519Signature2020`.
- The `proofValue` is multibase-encoded (z-base58btc) over the raw
  64-byte Ed25519 signature.
- Implementations MUST accept both hex-encoded and multibase
  z-base58btc encoded signatures for interoperability.  The canonical
  output format is hex-encoded for v1.0.x.

## 14.2. AES-256-GCM

Used for Memory Vault encryption (Section 8):

- Key size: 256 bits.
- IV size: 96 bits (12 bytes).  MUST be generated using a CSPRNG.
- Tag size: 128 bits (16 bytes).
- Each encryption operation MUST use a unique IV.
- Implementations MUST NOT reuse an IV with the same key.

## 14.3. Merkle Trees

Batch proofs (Section 4.6) use binary Merkle trees:

- Leaf hash: `keccak256(0x00 || receipt_hash_bytes)`.
  The `0x00` prefix distinguishes leaves from internal nodes.
- Internal node: `keccak256(0x01 || min(left, right) || max(left, right))`.
  Sibling hashes are sorted before concatenation to produce a
  canonical tree regardless of insertion order.
  The `0x01` prefix distinguishes internal nodes from leaves.
- Proof: Array of sibling hashes from leaf to root.

Tree construction:

1. Compute leaf hashes for all receipts in the batch.
2. Sort leaf hashes lexicographically.
3. Build the tree bottom-up, pairing adjacent leaves.
4. If the number of leaves at any level is odd, the last leaf is
   promoted to the next level without hashing.

Implementations without domain separation (i.e., without the `0x00`
and `0x01` prefixes) MUST be accepted for backward compatibility with
early v1.0.x deployments.


# 15. Conformance

## 15.1. Conformance Levels

Three conformance levels are defined:

### 14.1.1. Level 1: Basic

- All artifacts MUST be valid JSON matching their respective schemas.
- All Hex256 hashes MUST be correctly computed.
- All Ed25519 signatures MUST be valid.
- The `@context` and `type` fields MUST be correct.

### 14.1.2. Level 2: Enhanced

All Level 1 requirements, plus:

- Snapshot hash chain integrity MUST be verified (prev_hash linkage).
- Work Receipt lifecycle ordering MUST be validated.
- Security Envelope constraints MUST be enforced at runtime.
- DNA frozen state MUST be respected.
- Lineage DAG MUST be acyclic.

### 14.1.3. Level 3: Full

All Level 2 requirements, plus:

- Anchoring receipts MUST be verified against the anchoring layer.
- Merkle batch proofs MUST be validated.
- Attestation signatures and expiry MUST be verified.
- Benchmark attestation claims MUST be verified.
- Trust signals MUST be derived only from verified Work Receipts.

## 15.2. Test Vectors

Implementations MUST pass the test vectors defined in
`test-vectors.json` (see Appendix B).

## 15.3. Test Vector Format

Each test vector is a JSON object with:

- `name` — String.  Short identifier (e.g., `"passport-hash-basic"`).
- `description` — String.  Human-readable description.
- `input` — Object.  Input data for the test.
- `expected_output` — Object.  Expected result.
- `notes` — String.  Additional context.  OPTIONAL.

## 15.4. Conformance Assertion

Implementations claiming conformance to this specification MUST
declare their conformance level and MUST pass all test vectors for
that level.  A conformance assertion has the form:

```
"This implementation conforms to APS v1.0 at Level [1|2|3]."
```


# 16. Security Considerations

## 16.1. Key Management

Agent identity is bound to an Ed25519 key pair.  Compromise of the
private key allows full impersonation of the agent, including signing
fraudulent passports, work receipts, and security envelopes.

Implementations MUST:

- Store private keys in hardware security modules (HSMs), secure
  enclaves, or equivalent protected storage where available.
- Never transmit private keys over unencrypted channels.
- Support key rotation by creating a new passport version with the
  new key, signed by the old key, and anchoring the transition.

Implementations SHOULD:

- Use OS-level keychain or secret management services.
- Implement key usage auditing.

## 16.2. Replay Attacks

Signatures are bound to the content of the signed document.  However,
a valid signed artifact could be replayed in a different context.

Mitigations:

- Work Receipts include timestamps and job identifiers that bind them
  to specific contexts.
- Verifiers SHOULD check that timestamps are within acceptable bounds.
- Snapshot versioning prevents replay of outdated passport states.
- Anchoring provides timestamp evidence that can be independently
  verified.

## 16.3. Timing Attacks

When verifying Ed25519 signatures or comparing hash values,
implementations MUST use constant-time comparison functions.
Variable-time comparison can leak information about the expected value
through timing side channels.

## 16.4. DID Resolution Attacks

The `did:key` method embeds the public key directly in the identifier,
avoiding external resolution.  However:

- If implementations support additional DID methods that require
  network resolution (e.g., `did:web`), they MUST validate the
  resolution result and SHOULD use DNSSEC-protected domains.
- Man-in-the-middle attacks during DID resolution could substitute
  a malicious public key.
- Implementations SHOULD cache resolved DIDs and detect changes.

## 16.5. Anchoring Provider Trust

Anchoring provides tamper evidence, not tamper prevention.  The
security of anchoring depends on the integrity of the underlying
ledger.

- Ethereum and similar blockchains provide strong tamper evidence
  through proof-of-stake consensus.
- Transparency logs provide tamper evidence through append-only
  semantics and gossip protocols.
- The `noop` provider provides NO security guarantees and MUST NOT
  be used in production.
- Implementations SHOULD support multiple anchoring providers to
  reduce single-provider risk.

## 16.6. Memory Vault Key Loss

Memory Vault encryption is designed to be irreversible without the
owner's key.  If the owner loses the encryption key:

- The vault contents are irrecoverable.  This is by design.
- The platform MUST NOT maintain any mechanism to recover vault
  contents without the key.
- Owners SHOULD maintain secure backups of their encryption keys.
- Implementations SHOULD warn owners about the consequences of key
  loss during vault creation.

## 16.7. Cross-Platform Attestation Trust

Attestations from external platforms carry varying levels of trust:

- An attestation is only as trustworthy as its issuer.
- Trust registries provide guidance but MUST NOT be the sole basis
  for trust decisions.
- Expired attestations MUST be rejected.
- Revoked attestations MUST be rejected when revocation information
  is available.
- Implementations SHOULD implement attestation freshness checks.

## 16.8. Canonicalization Attacks

Incorrect canonicalization can cause signature verification failures
or, worse, allow two different JSON documents to produce the same
canonical form:

- Implementations MUST use a conforming RFC 8785 implementation.
- Implementations MUST NOT use ad-hoc JSON serialization.
- Special attention is required for Unicode normalization: JCS
  operates on Unicode code points, not normalized forms.
- Numeric precision: implementations MUST handle IEEE 754
  double-precision correctly per RFC 8785 Section 3.2.2.5.

## 16.9. Denial of Service

- Deeply nested JSON structures could cause stack overflow during
  canonicalization.  Implementations SHOULD impose a maximum nesting
  depth (RECOMMENDED: 32 levels).
- Very large passport documents could consume excessive memory.
  Implementations SHOULD impose a maximum document size
  (RECOMMENDED: 1 MB).
- Merkle tree batch sizes should be bounded.  Implementations SHOULD
  impose a maximum batch size (RECOMMENDED: 65536 receipts).

## 16.10. Without Blockchain Anchoring

Implementations operating at Trust Level 1 (APS Basic) face the
following risks that cannot be mitigated without blockchain anchoring:

-  Timestamp forgery: Self-reported timestamps can be backdated or
   future-dated.  An agent could claim work was completed before it
   actually was.
-  Silent document replacement: A passport can be completely replaced
   without detection.  There is no proof-of-existence for the
   previous version.
-  Heritage fabrication: Lineage claims cannot be verified against an
   immutable record.  An agent could claim descent from a high-
   reputation ancestor without proof.
-  Attestation repudiation: An issuer can deny having issued an
   attestation, or silently revoke it without any verifiable record.
-  Split-brain identity: An agent could present different passports
   to different platforms with no way to detect the inconsistency.

These risks are acceptable in trusted, single-organization
environments but are critical vulnerabilities in open, multi-
organization agent ecosystems.


# 17. IANA Considerations

## 17.1. Media Types

### 17.1.1. application/agent-passport+json

Type name: application

Subtype name: agent-passport+json

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary (UTF-8 JSON)

Security considerations: See Section 15 of this document.

Interoperability considerations: See Section 14.

Published specification: This document.

Applications that use this media type: AI agent platforms, trust
  verification systems, agent registries.

Fragment identifier considerations: N/A

Additional information:
  - Deprecated alias names for this type: N/A
  - Magic number(s): N/A
  - File extension(s): .agent-passport.json
  - Macintosh file type code(s): N/A

Person & email address to contact for further information:
  Cezary Grotowski <c.grotowski@gmail.com>

Intended usage: COMMON

Restrictions on usage: N/A

Author: Cezary Grotowski

Change controller: IETF

### 17.1.2. application/work-receipt+json

Type name: application

Subtype name: work-receipt+json

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary (UTF-8 JSON)

Security considerations: See Section 15 of this document.

Published specification: This document.

Applications that use this media type: AI agent platforms, work
  verification systems.

Person & email address to contact for further information:
  Cezary Grotowski <c.grotowski@gmail.com>

Intended usage: COMMON

Author: Cezary Grotowski

Change controller: IETF

### 17.1.3. application/security-envelope+json

Type name: application

Subtype name: security-envelope+json

Required parameters: N/A

Optional parameters: N/A

Encoding considerations: binary (UTF-8 JSON)

Security considerations: See Section 15 of this document.

Published specification: This document.

Applications that use this media type: AI agent platforms, sandbox
  enforcement systems.

Person & email address to contact for further information:
  Cezary Grotowski <c.grotowski@gmail.com>

Intended usage: COMMON

Author: Cezary Grotowski

Change controller: IETF

## 17.2. URI Schemes

This specification uses the `did:key` URI scheme as defined by the
W3C Decentralized Identifiers specification [W3C.DID-CORE].  No new
URI scheme registration is requested.

## 17.3. Context URL

The canonical context URL for APS v1.0 is:

```
https://agentpassport.org/v1.0
```

This URL SHOULD resolve to a JSON-LD context document describing the
APS vocabulary.  Sub-contexts:

- `https://agentpassport.org/v1.0/dna` — Agent DNA context.
- `https://agentpassport.org/v1.0/vault` — Memory Vault context.


# 18. References

## 18.1. Normative References

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119,
  March 1997, <https://www.rfc-editor.org/rfc/rfc2119>.

- **[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve
  Digital Signature Algorithm (EdDSA)", RFC 8032,
  DOI 10.17487/RFC8032, January 2017,
  <https://www.rfc-editor.org/rfc/rfc8032>.

- **[RFC8785]** Rundgren, A., Jordan, B., and S. Erdtman, "JSON
  Canonicalization Scheme (JCS)", RFC 8785, DOI 10.17487/RFC8785,
  June 2020, <https://www.rfc-editor.org/rfc/rfc8785>.

- **[RFC6962]** Laurie, B., Langley, A., and E. Kasper, "Certificate
  Transparency", RFC 6962, DOI 10.17487/RFC6962, June 2013,
  <https://www.rfc-editor.org/rfc/rfc6962>.

## 18.2. Informative References

- **[W3C.DID-CORE]** Sporny, M., Longley, D., Sabadello, M., Reed,
  D., Steele, O., and C. Allen, "Decentralized Identifiers (DIDs)
  v1.0", W3C Recommendation, July 2022,
  <https://www.w3.org/TR/did-core/>.

- **[W3C.VC-DATA-MODEL]** Sporny, M., Longley, D., and D. Chadwick,
  "Verifiable Credentials Data Model v2.0", W3C Recommendation, 2024,
  <https://www.w3.org/TR/vc-data-model-2.0/>.

- **[KECCAK]** Bertoni, G., Daemen, J., Peeters, M., and G. Van
  Assche, "The Keccak SHA-3 submission", 2011,
  <https://keccak.team/keccak.html>.

- **[MCP]** "Model Context Protocol", 2024,
  <https://modelcontextprotocol.io/>.

- **[A2A]** "Agent-to-Agent Protocol", Google, 2025,
  <https://google.github.io/A2A/>.


# Appendix A: JSON Schemas

The following JSON Schema files define the normative structure of APS
artifacts.  Implementations MUST validate artifacts against these
schemas at all conformance levels.

| Schema File                      | Artifact                |
|----------------------------------|-------------------------|
| `agent-passport.schema.json`     | Agent Passport          |
| `work-receipt.schema.json`       | Work Receipt            |
| `security-envelope.schema.json`  | Security Envelope       |
| `dna.schema.json`                | Agent DNA (standalone)  |
| `memory-vault.schema.json`       | Memory Vault            |
| `anchoring.schema.json`          | Anchor Receipt          |

Schema files are available at:
`https://agentpassport.org/v1.0/schemas/`

And in the specification repository under `spec/`.


# Appendix B: Test Vectors

Normative test vectors are defined in `spec/test-vectors.json` in the
APS repository.  The test vector file contains a JSON array of test
vector objects as defined in Section 14.3.

Test vectors cover:

1. **Canonicalization** — Input JSON and expected canonical output.
2. **Hashing** — Input object and expected Keccak-256 Hex256 hash.
3. **Signing** — Input object, private key, and expected signature.
4. **Verification** — Signed artifact and expected verification result.
5. **Merkle tree** — Set of receipt hashes, expected root, and proofs.
6. **Snapshot chain** — Sequence of snapshots with expected hash chain.

Implementations claiming any conformance level MUST pass all test
vectors for that level.  Test vectors are tagged with their minimum
required conformance level.


# Appendix C: Implementation Notes

## C.1. Go SDK

The reference Go implementation is in the `go/` directory of the APS
repository.  Key packages:

- `aps/canonical` — RFC 8785 canonicalization.
- `aps/crypto` — Ed25519 signing/verification, Keccak-256 hashing.
- `aps/merkle` — Merkle tree construction and proof generation.
- `aps/passport` — Passport creation, validation, and serialization.
- `aps/receipt` — Work Receipt lifecycle management.
- `aps/envelope` — Security Envelope enforcement.
- `aps/anchor` — Anchoring provider interface and implementations.

The Go SDK targets Go 1.21+ and uses `golang.org/x/crypto` for
Ed25519 and a pure-Go Keccak-256 implementation.

## C.2. Python SDK

The Python SDK is in the `python/` directory.  Key modules:

- `aps.canonical` — JCS canonicalization.
- `aps.crypto` — Cryptographic operations using `pynacl` (Ed25519)
  and `pysha3` or `pycryptodome` (Keccak-256).
- `aps.passport` — Passport management.
- `aps.receipt` — Work Receipt management.
- `aps.envelope` — Security Envelope management.
- `aps.anchor` — Anchoring interface.

The Python SDK targets Python 3.10+ and is available via PyPI as
`agent-passport-standard`.

## C.3. TypeScript SDK

The TypeScript SDK is in the `typescript/` directory.  Key modules:

- `@aps/canonical` — JCS canonicalization using `canonicalize` npm
  package.
- `@aps/crypto` — Ed25519 via `@noble/ed25519`, Keccak-256 via
  `@noble/hashes`.
- `@aps/passport` — Passport management.
- `@aps/receipt` — Work Receipt management.
- `@aps/envelope` — Security Envelope management.
- `@aps/anchor` — Anchoring interface.

The TypeScript SDK targets ES2022+ and Node.js 18+.  It is published
to npm as `@agent-passport/sdk`.

## C.4. Common Implementation Pitfalls

1. **Using SHA-3 instead of Keccak-256**: The NIST SHA-3 (FIPS 202)
   produces different output than Keccak-256.  Ensure your library
   implements the original Keccak, not NIST SHA-3.

2. **Non-canonical JSON**: Using `JSON.stringify` or equivalent without
   JCS compliance will produce incorrect hashes.  Always use a
   conforming RFC 8785 implementation.

3. **Mutable genesis_owner**: The genesis_owner field is immutable.
   Implementations must reject any passport update that modifies it.

4. **IV reuse in AES-256-GCM**: Reusing an IV with the same key
   completely breaks GCM security.  Always generate a fresh random IV.

5. **Variable-time comparison**: Using `==` to compare hashes or
   signatures leaks timing information.  Use constant-time comparison.


# Authors' Addresses

Cezary Grotowski

Email: c.grotowski@gmail.com
