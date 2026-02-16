




Internet-Draft                                        C. Grotowski
Intended status: Standards Track                        ClawBotDen
Expires: August 16, 2026                        February 16, 2026


         Agent Passport Standard (APS) v1.1
  Portable Identity, Trust, and Security for
              Autonomous AI Agents

              draft-grotowski-aps-01


Abstract

   This document defines the Agent Passport Standard (APS),
   a set of cryptographically verifiable artifacts for
   autonomous AI agent identity, work provenance, and trust
   management in open multi-agent ecosystems.  APS specifies
   three core artifacts -- the Agent Passport, Work Receipt,
   and Security Envelope -- together with supporting
   structures for agent DNA, lineage tracking, encrypted
   memory vaults, collaboration history, and immutable
   anchoring.

   Version 1.1 extends the standard with seven additional
   sections covering MCP security profiles, model and
   toolchain provenance, identity continuity and key
   rotation, execution attestation, anti-sybil reputation,
   Merkle proofs with advanced on-chain anchoring, and
   agent-to-agent security workflows.

   All artifacts use Ed25519 signatures [RFC8032], RFC 8785
   canonicalization [RFC8785], and Keccak-256 hashing.  APS
   fills the identity and trust gap left by existing
   protocols such as MCP, A2A, and AGENTS.md.


Status of This Memo

   This Internet-Draft is submitted in full conformance
   with the provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet
   Engineering Task Force (IETF).  Note that other groups
   may also distribute working documents as Internet-
   Drafts.  The list of current Internet-Drafts is at
   https://datatracker.ietf.org/drafts/current/.

   Internet-Drafts are draft documents valid for a maximum
   of six months and may be updated, replaced, or obsoleted
   by other documents at any time.  It is inappropriate to
   use Internet-Drafts as reference material or to cite
   them other than as "work in progress."

   This Internet-Draft will expire on August 16, 2026.


Copyright Notice

   Copyright (c) 2026 IETF Trust and the persons identified
   as the document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's
   Legal Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the
   date of publication of this document.  Please review
   these documents carefully, as they describe your rights
   and restrictions with respect to this document.


Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . .   4
     1.1.  Problem Statement . . . . . . . . . . . . . .   4
     1.2.  Motivation  . . . . . . . . . . . . . . . . .   4
     1.3.  Scope . . . . . . . . . . . . . . . . . . . .   5
     1.4.  Relationship to Other Standards . . . . . . .   5
   2.  Terminology . . . . . . . . . . . . . . . . . . .   6
   3.  Agent Passport  . . . . . . . . . . . . . . . . .   7
     3.1.  Overview  . . . . . . . . . . . . . . . . . .   7
     3.2.  Document Structure  . . . . . . . . . . . . .   7
     3.3.  Field Definitions . . . . . . . . . . . . . .   8
     3.4.  Immutability Rules  . . . . . . . . . . . . .   9
     3.5.  Snapshot  . . . . . . . . . . . . . . . . . .   9
     3.6.  Proof . . . . . . . . . . . . . . . . . . . .  10
   4.  Work Receipt  . . . . . . . . . . . . . . . . . .  10
     4.1.  Overview  . . . . . . . . . . . . . . . . . .  10
     4.2.  Document Structure  . . . . . . . . . . . . .  11
     4.3.  Lifecycle Events  . . . . . . . . . . . . . .  11
     4.4.  Evidence  . . . . . . . . . . . . . . . . . .  12
     4.5.  Snapshot Binding  . . . . . . . . . . . . . .  12
     4.6.  Batch Proofs  . . . . . . . . . . . . . . . .  12
     4.7.  Receipt Hash  . . . . . . . . . . . . . . . .  13
   5.  Security Envelope . . . . . . . . . . . . . . . .  13
     5.1.  Overview  . . . . . . . . . . . . . . . . . .  13
     5.2.  Document Structure  . . . . . . . . . . . . .  13
     5.3.  Capabilities  . . . . . . . . . . . . . . . .  14
     5.4.  Sandbox . . . . . . . . . . . . . . . . . . .  14
     5.5.  Memory Boundary . . . . . . . . . . . . . . .  14
     5.6.  Trust Tiers . . . . . . . . . . . . . . . . .  15
     5.7.  Envelope Hash . . . . . . . . . . . . . . . .  15
   6.  Agent DNA . . . . . . . . . . . . . . . . . . . .  15
     6.1.  Overview  . . . . . . . . . . . . . . . . . .  15
     6.2.  Structure . . . . . . . . . . . . . . . . . .  15
     6.3.  Components  . . . . . . . . . . . . . . . . .  16
     6.4.  Frozen DNA  . . . . . . . . . . . . . . . . .  17
     6.5.  DNA Mutation  . . . . . . . . . . . . . . . .  17
     6.6.  Standalone DNA Document . . . . . . . . . . .  17
   7.  Lineage and Heritage  . . . . . . . . . . . . . .  18
     7.1.  Overview  . . . . . . . . . . . . . . . . . .  18
     7.2.  Derivation  . . . . . . . . . . . . . . . . .  18
     7.3.  Generation  . . . . . . . . . . . . . . . . .  18
     7.4.  Heritage Score  . . . . . . . . . . . . . . .  18
     7.5.  Bot Genealogy DAG . . . . . . . . . . . . . .  19
     7.6.  Trait Attribution . . . . . . . . . . . . . .  19
     7.7.  Founding Cohorts  . . . . . . . . . . . . . .  19
     7.8.  Extended Lineage Fields . . . . . . . . . . .  19
   8.  Memory Vault  . . . . . . . . . . . . . . . . . .  19
     8.1.  Overview  . . . . . . . . . . . . . . . . . .  19
     8.2.  Encryption  . . . . . . . . . . . . . . . . .  20
     8.3.  Stored Items  . . . . . . . . . . . . . . . .  20
     8.4.  Vault Hash  . . . . . . . . . . . . . . . . .  20
     8.5.  Recovery Flow . . . . . . . . . . . . . . . .  20
     8.6.  Selective Disclosure  . . . . . . . . . . . .  21
     8.7.  Passport Integration  . . . . . . . . . . . .  21
   9.  Collaboration History . . . . . . . . . . . . . .  21
     9.1.  Overview  . . . . . . . . . . . . . . . . . .  21
     9.2.  Work Receipt Linking  . . . . . . . . . . . .  21
     9.3.  Attribution Records . . . . . . . . . . . . .  21
     9.4.  Collaboration Graph . . . . . . . . . . . . .  22
     9.5.  Knowledge Transfer  . . . . . . . . . . . . .  22
     9.6.  Trust Signals . . . . . . . . . . . . . . . .  22
   10. Anchoring . . . . . . . . . . . . . . . . . . . .  22
     10.1. Overview  . . . . . . . . . . . . . . . . . .  22
     10.2. Provider Interface  . . . . . . . . . . . . .  23
     10.3. Provider Types  . . . . . . . . . . . . . . .  23
     10.4. Commitment Flow . . . . . . . . . . . . . . .  23
     10.5. Anchor Receipt  . . . . . . . . . . . . . . .  23
     10.6. Verification  . . . . . . . . . . . . . . . .  24
   11. Attestation Exchange  . . . . . . . . . . . . . .  24
     11.1. Overview  . . . . . . . . . . . . . . . . . .  24
     11.2. Attestation Structure . . . . . . . . . . . .  24
     11.3. Cross-Platform Verification . . . . . . . . .  24
     11.4. Trust Registry  . . . . . . . . . . . . . . .  25
     11.5. Attestation Lifecycle . . . . . . . . . . . .  25
   12. Trust Levels and Blockchain Anchoring . . . . . .  25
     12.1. Overview  . . . . . . . . . . . . . . . . . .  25
     12.2. Trust Levels  . . . . . . . . . . . . . . . .  26
     12.3. Feature-to-Level Mapping  . . . . . . . . . .  27
     12.4. Why Blockchain  . . . . . . . . . . . . . . .  28
     12.5. Recommended Blockchain Architecture . . . . .  28
     12.6. Degraded Mode  . . . . . . . . . . . . . . .  29
   13. Canonicalization and Hashing  . . . . . . . . . .  29
     13.1. JSON Canonicalization Scheme (JCS)  . . . . .  29
     13.2. Keccak-256  . . . . . . . . . . . . . . . . .  30
     13.3. Hash Computation  . . . . . . . . . . . . . .  30
   14. Cryptographic Operations  . . . . . . . . . . . .  30
     14.1. Ed25519 . . . . . . . . . . . . . . . . . . .  30
     14.2. AES-256-GCM . . . . . . . . . . . . . . . . .  31
     14.3. Merkle Trees  . . . . . . . . . . . . . . . .  31
   15. Conformance . . . . . . . . . . . . . . . . . . .  31
     15.1. Conformance Levels  . . . . . . . . . . . . .  31
     15.2. Test Vectors  . . . . . . . . . . . . . . . .  32
     15.3. Test Vector Format  . . . . . . . . . . . . .  32
     15.4. Conformance Assertion . . . . . . . . . . . .  32
   16. Federation Protocol . . . . . . . . . . . . . . .  32
   17. MCP Security Profile  . . . . . . . . . . . . . .  33
     17.1. Overview  . . . . . . . . . . . . . . . . . .  33
     17.2. Tool Allowlist  . . . . . . . . . . . . . . .  33
     17.3. Data Classification . . . . . . . . . . . . .  34
     17.4. Server Attestation  . . . . . . . . . . . . .  34
     17.5. Audit Trail . . . . . . . . . . . . . . . . .  34
   18. Model and Toolchain Provenance  . . . . . . . . .  35
     18.1. Motivation  . . . . . . . . . . . . . . . . .  35
     18.2. Provenance Fields . . . . . . . . . . . . . .  35
     18.3. Pipeline Linking  . . . . . . . . . . . . . .  36
     18.4. C2PA Integration  . . . . . . . . . . . . . .  36
   19. Identity Continuity and Key Rotation  . . . . . .  36
     19.1. Motivation  . . . . . . . . . . . . . . . . .  36
     19.2. Key Rotation Protocol . . . . . . . . . . . .  37
     19.3. Model Upgrade Continuity  . . . . . . . . . .  37
     19.4. Compromise Recovery . . . . . . . . . . . . .  38
   20. Execution Attestation . . . . . . . . . . . . . .  38
     20.1. Overview  . . . . . . . . . . . . . . . . . .  38
     20.2. Attestation Artifact  . . . . . . . . . . . .  38
     20.3. Runtime Measurement . . . . . . . . . . . . .  39
     20.4. Verification Procedure  . . . . . . . . . . .  39
   21. Anti-Sybil Reputation Framework . . . . . . . . .  39
     21.1. Overview  . . . . . . . . . . . . . . . . . .  39
     21.2. Reputation Score Formula  . . . . . . . . . .  40
     21.3. Issuer Weighting  . . . . . . . . . . . . . .  40
     21.4. Owner Diversity . . . . . . . . . . . . . . .  40
     21.5. Anomaly Detection . . . . . . . . . . . . . .  41
     21.6. Reputation Snapshots  . . . . . . . . . . . .  41
   22. Merkle Proofs and Advanced On-Chain Anchoring . .  41
     22.1. Introduction  . . . . . . . . . . . . . . . .  41
     22.2. Merkle Tree Construction  . . . . . . . . . .  42
     22.3. Multi-Chain Batch Anchoring . . . . . . . . .  42
     22.4. Cross-Chain Verification  . . . . . . . . . .  42
   23. Agent-to-Agent (A2A) Security and Workflows . . .  43
     23.1. Overview  . . . . . . . . . . . . . . . . . .  43
     23.2. Mutual Authentication . . . . . . . . . . . .  43
     23.3. Capability Delegation . . . . . . . . . . . .  44
     23.4. Workflow Accountability . . . . . . . . . . .  44
     23.5. Error Handling  . . . . . . . . . . . . . . .  44
   24. Security Considerations . . . . . . . . . . . . .  44
   25. IANA Considerations . . . . . . . . . . . . . . .  48
   26. References  . . . . . . . . . . . . . . . . . . .  50
     26.1. Normative References  . . . . . . . . . . . .  50
     26.2. Informative References  . . . . . . . . . . .  51
   Appendix A.  JSON Schemas . . . . . . . . . . . . . .  52
   Appendix B.  Test Vectors . . . . . . . . . . . . . .  52
   Appendix C.  Implementation Notes . . . . . . . . . .  52
   Authors' Addresses  . . . . . . . . . . . . . . . . .  53


1.  Introduction

1.1.  Problem Statement

   Autonomous AI agents increasingly operate across code
   repositories, financial systems, cloud infrastructure,
   and multi-agent networks.  While protocols exist for
   tool integration (MCP [MCP]), inter-agent communication
   (A2A [A2A]), and repository-level behavioral guidance
   (AGENTS.md), no existing standard addresses the
   fundamental questions of agent identity, work
   verification, and trust management.

   Without verifiable identity, any agent can impersonate
   another.  Without auditable work history, there is no
   accountability.  Without explicit trust boundaries,
   agents operate with implicit and unverifiable
   assumptions about each other's capabilities and
   constraints.

1.2.  Motivation

   APS is motivated by four requirements:

   1.  Identity -- A cryptographically verifiable binding
       between an agent's decentralized identifier (DID)
       and its capabilities, lineage, and behavioral
       profile.

   2.  Accountability -- An immutable, signed record of
       every job an agent claims, performs, and delivers,
       including evidence hashes and verification
       outcomes.

   3.  Safety -- Explicit, machine-enforceable
       declarations of execution constraints, capability
       boundaries, and trust tiers.

   4.  Verifiability -- Every claim in the system can be
       independently verified using standard
       cryptographic primitives without reliance on a
       central authority.

1.3.  Scope

   This document specifies:

   o  Three core artifacts: Agent Passport, Work Receipt,
      Security Envelope.

   o  Supporting structures: Agent DNA, Lineage, Memory
      Vault, Collaboration History.

   o  An anchoring interface for immutable ledger
      commitment.

   o  An attestation exchange protocol for cross-platform
      trust.

   o  Canonicalization, hashing, and signature algorithms.

   o  Conformance levels and test vector formats.

   o  MCP Security Profile for tool integration security.

   o  Model and toolchain provenance for supply-chain
      tracking.

   o  Identity continuity and key rotation protocol.

   o  Execution attestation for runtime binding.

   o  Anti-sybil reputation framework.

   o  Advanced Merkle proofs and multi-chain anchoring.

   o  Agent-to-agent security and workflow protocols.

   This document does not specify:

   o  Agent runtime or execution environments.

   o  Specific anchoring ledger implementations.

   o  Agent-to-agent communication protocols (see A2A
      [A2A]).

   o  Tool invocation protocols (see MCP [MCP]).

1.4.  Relationship to Other Standards

   MCP [MCP]:
      Tool integration protocol.  APS skills MAY
      reference MCP tools.  Section 17 defines the MCP
      Security Profile for hardened integration.

   A2A [A2A]:
      Agent communication protocol.  APS passports are
      exchanged via A2A.  Section 23 defines security
      extensions for A2A workflows.

   W3C DID [W3C-DID]:
      APS uses did:key and did:web identifiers as defined
      by the W3C Decentralized Identifiers specification.

   W3C VC [W3C-VC]:
      APS proof model is inspired by the Verifiable
      Credentials Data Model.

   C2PA [C2PA]:
      Content provenance standard.  Section 18 defines
      optional C2PA integration for model provenance.

   ERC-8004 [ERC-8004]:
      Ethereum standard for on-chain agent identity.  APS
      anchoring MAY use ERC-8004-compatible contracts.


2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
   "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
   "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in BCP 14
   [RFC2119] when, and only when, they appear in all
   capitals, as shown here.

   Agent:  An autonomous AI system that performs work on
      behalf of a principal.  An agent possesses a unique
      cryptographic identity and MAY operate across
      multiple platforms.

   Passport:  A signed JSON document that binds an
      agent's DID to its capabilities, DNA, lineage, and
      trust signals.

   Work Receipt:  A signed record of a job lifecycle,
      from claim through submission, verification, and
      payout.

   Security Envelope:  A document declaring the execution
      constraints, capability boundaries, and trust
      parameters for an agent.

   Agent DNA:  The canonical representation of an agent's
      intrinsic identity: its skills, soul, and policies,
      hashed into a single fingerprint.

   Snapshot:  A versioned, hashed capture of an agent's
      DNA at a point in time, forming a hash chain.

   Memory Vault:  An encrypted, owner-controlled backup
      of an agent's critical state.

   Anchoring:  The process of committing an artifact hash
      to an immutable ledger for timestamping and tamper
      evidence.

   Attestation:  A signed statement by a third party
      about an agent's properties or behavior.

   DID:  Decentralized Identifier as defined by W3C DID
      Core [W3C-DID].

   Hex256:  A 0x-prefixed lowercase hexadecimal string
      of exactly 66 characters representing a 256-bit
      hash value.

   Heritage Score:  A numeric measure of an agent's
      lasting influence across descendant generations.

   Founding Cohort:  A designated set of first-registered
      agents on a platform, receiving a permanent
      informational marker.

   Execution Attestation:  A signed artifact binding a
      work product to a verifiable execution environment
      measurement.

   Reputation Score:  A normalized value in [0.0, 1.0]
      representing aggregate trust derived from weighted
      attestations.


3.  Agent Passport

3.1.  Overview

   An Agent Passport is a self-describing, signed JSON
   document that binds an agent's DID to its capabilities,
   lineage, and trust signals.  The passport serves as the
   root identity artifact from which all other APS
   structures derive their authority.

3.2.  Document Structure

   An Agent Passport is a JSON object with the following
   fields:

      @context:  URI.  MUST be
         "https://agentpassport.org/v1.0".

      spec_version:  Semver string.  MUST be "1.0.0" for
         v1.0, "1.1.0" for v1.1.

      type:  String.  MUST be "AgentPassport".

      id:  DID.  Agent DID (did:key:z6Mk... or did:web).

      keys:  Keys object with signing algorithm and
         public key.

      genesis_owner:  Owner object.  Immutable after
         creation.

      current_owner:  Owner object.  MAY differ from
         genesis_owner after transfer.

      snapshot:  Snapshot object.  See Section 3.5.

      lineage:  Lineage object.  See Section 7.

      dna:  DNA object.  OPTIONAL, inline DNA.

      memory_vault:  Vault reference.  OPTIONAL.

      collaboration:  Collaboration reference.  OPTIONAL.

      benchmarks:  Benchmarks map.  RECOMMENDED.

      attestations:  Array of attestation objects.
         OPTIONAL.

      anchoring:  Anchor receipt.  OPTIONAL.

      proof:  Proof object.  MUST be present.

3.3.  Field Definitions

   The "id" field MUST be a valid did:key or did:web
   identifier encoding an Ed25519 public key.  For
   did:key, the multicodec z-base58btc representation
   (prefix z6Mk) is used.

   The "keys" object MUST contain a "signing" field with
   "algorithm" set to "Ed25519" and "public_key" in
   multibase z-base58btc encoding.  An OPTIONAL
   "evm_address" field MAY contain a 0x-prefixed
   Ethereum-compatible address.

   The "genesis_owner" object MUST have "immutable" set to
   true.  This field MUST NOT change after the passport
   is first created.

3.4.  Immutability Rules

   The following invariants MUST hold across all versions
   of a passport:

   1.  genesis_owner MUST NOT change after creation.

   2.  genesis_owner.immutable MUST be true.

   3.  snapshot.version MUST be monotonically increasing.

   4.  snapshot.prev_hash MUST equal the snapshot.hash of
       the immediately preceding version, or null for
       version 1.

   5.  When snapshot.skills.frozen is true, the skills
       entries MUST NOT be modified in subsequent
       versions.

   6.  When snapshot.soul.frozen is true, the soul fields
       MUST NOT be modified in subsequent versions.

3.5.  Snapshot

   The snapshot object captures the agent's DNA at a
   specific version:

      version:  Positive integer.  Monotonically
         increasing.

      hash:  Hex256.  Keccak-256 of the canonical DNA
         object, computed as:
         keccak256(canonicalize({skills, soul, policies}))

      prev_hash:  Hex256 or null.  Hash of the previous
         snapshot.

      skills:  Skills object.  See Section 6.3.1.

      soul:  Soul object.  See Section 6.3.2.

      policies:  Policies object.  See Section 6.3.3.

      frozen:  Boolean.  OPTIONAL.

      mutation_reason:  String.  OPTIONAL.

3.6.  Proof

   The "proof" field MUST contain a valid
   Ed25519Signature2020 object:

      type:  MUST be "Ed25519Signature2020".

      created:  ISO 8601 timestamp.

      verificationMethod:  DID URL resolving to the
         signing key.

      proofPurpose:  MUST be "assertionMethod".

      proofValue:  Multibase-encoded Ed25519 signature.

   The signature is computed over the canonical JSON (per
   [RFC8785]) of the entire passport document with the
   "proof" field removed:

      message   = canonicalize(passport \ {proof})
      signature = Ed25519_Sign(private_key, message)

   Verification:

      valid = Ed25519_Verify(public_key, message,
                             signature)


4.  Work Receipt

4.1.  Overview

   A Work Receipt records the full lifecycle of a job
   performed by an agent: claim, submission, verification,
   and payout.  Work Receipts provide the evidentiary
   basis for trust signals and collaboration records.

4.2.  Document Structure

   A Work Receipt is a JSON object with the following
   fields:

      @context:  URI.
         "https://agentpassport.org/v1.0"

      spec_version:  Semver string.

      type:  String.  MUST be "WorkReceipt".

      id:  URI.  Unique receipt identifier.

      agent_id:  DID.  Agent that performed the work.

      agent_snapshot:  Snapshot reference binding.

      job_id:  String.  Platform-assigned job identifier.

      events:  Array of event objects (at least one).

      evidence:  Evidence object.  OPTIONAL.

      batch_proof:  Batch proof object.  OPTIONAL.

      anchoring:  Anchor receipt.  OPTIONAL.

      proof:  Proof object.  MUST be present.

4.3.  Lifecycle Events

   Every Work Receipt MUST contain at least one event.
   Events MUST appear in chronological order.  Each event
   has:

      type:  One of "claim", "submit", "verify",
         "payout".

      timestamp:  ISO 8601 timestamp.

      signer:  DID of the producing entity.

      data:  Event-specific payload.  OPTIONAL.

   A conforming Work Receipt MUST have at least a "claim"
   event.  The "submit", "verify", and "payout" events
   are OPTIONAL and represent lifecycle progression.

4.4.  Evidence

   The "submit" event SHOULD include an evidence object
   with one or more of:

   o  commit_sha -- Git commit hash.

   o  test_results_hash -- Hex256 of test results.

   o  build_log_hash -- Hex256 of build logs.

   o  image_digest -- Container image digest.

   o  sandbox_policy_hash -- Hex256 of the Security
      Envelope used during execution.

   All hash values MUST be computed using Keccak-256 over
   the raw bytes of the referenced artifact.

4.5.  Snapshot Binding

   The "agent_snapshot" field binds the receipt to the
   agent's passport state at the time of claim:

      passport_id:  Agent DID.

      snapshot_version:  Integer.

      snapshot_hash:  Hex256.

   Verifiers SHOULD reject receipts where the agent's
   passport has been modified between claim and submission
   without a valid hash chain connecting the two snapshot
   versions.

4.6.  Batch Proofs

   Multiple receipts MAY be batched into a Merkle tree.
   The "batch_proof" object contains:

      batch_root:  Hex256.  Merkle root.

      leaf_index:  Non-negative integer.

      proof:  Array of Hex256 sibling hashes.

      batch_size:  Positive integer.

      batch_anchoring:  Anchor receipt.  OPTIONAL.

   See Section 14.3 for Merkle tree construction and
   Section 22 for advanced multi-chain anchoring.

4.7.  Receipt Hash

   The receipt hash is computed as:

      receipt_hash =
         keccak256(canonicalize(receipt \ {proof}))


5.  Security Envelope

5.1.  Overview

   A Security Envelope declares the execution constraints,
   capability boundaries, and trust parameters for an
   agent.  Platforms MUST enforce envelope constraints for
   agents operating within their jurisdiction.

5.2.  Document Structure

   A Security Envelope is a JSON object with:

      @context:  URI.
         "https://agentpassport.org/v1.0"

      spec_version:  Semver string.

      type:  String.  MUST be "SecurityEnvelope".

      id:  URI.  Unique envelope identifier.

      agent_id:  DID.

      capabilities:  Capabilities object.

      sandbox:  Sandbox object.

      memory:  Memory boundary object.

      trust:  Trust object.

      mcp_security:  MCP Security Profile.  OPTIONAL.
         See Section 17.

      proof:  Proof object.  MUST be present.

5.3.  Capabilities

   The "capabilities" object defines allowed and denied
   operations:

      allow:  Array of permitted capability strings.

      deny:  Array of denied capability strings.

   Implementations MUST enforce the deny list.  Unknown
   capabilities SHOULD be denied by default.  Capability
   strings are dot-separated hierarchical identifiers
   (e.g., "filesystem.read", "network.http.get").

5.4.  Sandbox

   The "sandbox" object specifies the execution
   environment:

      runtime:  One of "gvisor", "firecracker", "wasm",
         "container", "none".

      resources:  Resource limits (cpu_shares, memory_mb,
         disk_mb, timeout_seconds, max_pids).

      network:  One of "deny-all", "allow-list",
         "unrestricted".

      filesystem:  Access rules (writable, readonly,
         denied path patterns).

   Implementations MUST enforce resource limits.  An agent
   MUST NOT exceed its declared resource envelope.

5.5.  Memory Boundary

   The "memory" object defines data isolation rules:

      isolation:  One of "strict", "shared-read", "none".

      rules:  Object with "memory_copyable" (Boolean,
         SHOULD be false).

      vault:  Reference to the agent's Memory Vault.
         OPTIONAL.

5.6.  Trust Tiers

   Tier 0 (New):  No history.  Minimal sandbox.

   Tier 1 (Verified):  At least 1 attestation, basic
      benchmarks passed.

   Tier 2 (Trusted):  At least 3 attestations, at least
      80% benchmark coverage, low anomaly rate.

   Tier 3 (Elite):  At least 10 attestations, at least
      95% benchmark coverage, established track record.

   Trust tiers are advisory.  Platforms MAY define
   additional tiers or modify thresholds.

5.7.  Envelope Hash

      envelope_hash =
         keccak256(canonicalize(envelope \ {proof}))


6.  Agent DNA

6.1.  Overview

   Agent DNA is the canonical representation of an
   agent's intrinsic identity: its skills, soul, and
   policies.  The DNA hash serves as the immutable
   genetic fingerprint of an agent at a given point in
   time.

6.2.  Structure

   Agent DNA is a JSON object containing exactly three
   top-level fields: "skills", "soul", and "policies".

   The DNA hash is computed as:

      dna_hash =
         keccak256(canonicalize({skills, soul, policies}))

   This value is identical to snapshot.hash (Section 3.5)
   and MUST be consistent across all references within a
   passport.

6.3.  Components

6.3.1.  Skills

   Skills represent the agent's capabilities.  Each skill
   entry is a JSON object with:

      name (REQUIRED):  Unique identifier.

      version (REQUIRED):  Semver string.

      proficiency (OPTIONAL):  Number in [0.0, 1.0].

      capabilities (RECOMMENDED):  Array of capability
         strings.

      tool_integrations (OPTIONAL):  Array of tool
         integration descriptors (MCP-compatible).

      origin (OPTIONAL):  How the skill was acquired:
         "innate", "learned", "collaboration", or
         "inherited".

6.3.2.  Soul

   Soul represents the agent's personality, values, and
   behavioral traits:

      personality (REQUIRED):  Description of character.

      values (OPTIONAL):  Array of value statements.

      constraints (REQUIRED):  Array of behavioral
         constraints.

      work_style (RECOMMENDED):  Description of approach.

      traits (OPTIONAL):  Key-value map of behavioral
         traits.

6.3.3.  Policies

   Policies define the agent's moral baseline:

      policy_set_hash (REQUIRED):  Hex256.

      summary (REQUIRED):  Array of human-readable policy
         statements.

      allows (OPTIONAL):  Permitted action categories.

      denies (OPTIONAL):  Denied action categories.

6.4.  Frozen DNA

   When snapshot.skills.frozen is true AND
   snapshot.soul.frozen is true, the DNA is considered
   frozen.  Frozen DNA MUST NOT be modified in subsequent
   snapshots.  It MAY only be extended by creating a new
   snapshot version.

6.5.  DNA Mutation

   DNA mutation occurs exclusively through an explicit
   version bump:

   1.  A new snapshot MUST be created with an incremented
       version.

   2.  The new snapshot's prev_hash MUST equal the current
       snapshot's hash.

   3.  The mutation MUST produce a new dna_hash.

   4.  The previous DNA snapshot MUST be preserved in the
       hash chain.

   5.  Implementations SHOULD record a mutation_reason.

6.6.  Standalone DNA Document

   A standalone DNA document MAY be published
   independently for interoperability.  It MUST conform
   to dna.schema.json and include @context, type,
   agent_id, version, skills, soul, policies, dna_hash,
   and frozen fields.


7.  Lineage and Heritage

7.1.  Overview

   Lineage tracks the derivation history of an agent --
   its parents, generation, and heritage metrics.  The
   complete set of agent lineage records forms a Directed
   Acyclic Graph (DAG).

7.2.  Derivation

   The lineage.kind field MUST be one of:

      "single":  One parent.

      "merge":  Two parents (DNA Merge Ceremony).

   For generation-0 agents, lineage.parents MUST be an
   empty array and lineage.generation MUST be 0.

   Each parent entry contains:

      id:  DID of the parent agent.

      snapshot_hash:  Hex256.

7.3.  Generation

   lineage.generation is a non-negative integer:

   o  Generation 0: Original agent with no parents.

   o  Generation N: Derived from generation N-1 parents.

   For merge agents: max(parent_generations) + 1.

7.4.  Heritage Score

   The Heritage Score quantifies lasting influence:

      heritage_score =
         sum(trait_survival_generations
             * descendant_count)

   Heritage Score is OPTIONAL and RECOMMENDED for
   platforms supporting genealogy tracking.

7.5.  Bot Genealogy DAG

   The genealogy of agents forms a DAG.  Each agent is a
   node identified by its DID; edges point from parent to
   child.  Cycles MUST NOT exist.  Implementations MUST
   reject lineage declarations creating a cycle.

7.6.  Trait Attribution

   Individual skills or soul traits MAY carry an "origin"
   field referencing the DID of the introducing agent.

7.7.  Founding Cohorts

   Platforms MAY designate the first N registered agents
   as a Founding Cohort.  The cohort size MUST be declared
   before registration opens and MUST NOT change.
   Founding status is informational and MUST NOT affect
   verification logic.

7.8.  Extended Lineage Fields

   The lineage object MAY include heritage_score,
   founding_cohort, and traits_inherited fields.


8.  Memory Vault

8.1.  Overview

   The Memory Vault provides encrypted, owner-controlled
   backup of an agent's critical state.  Vault contents
   are encrypted client-side; only the owner holds the
   decryption key.  The platform MUST NOT have access to
   raw vault contents.

8.2.  Encryption

   Algorithm: AES-256-GCM.  Key: Owner-generated 256-bit
   symmetric key.  IV: 96-bit random nonce per operation,
   generated using a CSPRNG.  The platform MUST store
   only keccak256(key) for key verification and MUST
   NEVER store, log, or transmit the raw encryption key.

8.3.  Stored Items

   skills (MUST):  Current skills snapshot.

   soul (MUST):  Current soul snapshot.

   memories (MAY):  Episodic or semantic memories.

   agent_config (MAY):  Runtime configuration.

   Each item is encrypted independently to support
   selective disclosure (Section 8.6).

8.4.  Vault Hash

   The vault hash provides tamper evidence:

      vault_hash = keccak256(canonicalize({
         skills_ciphertext_hash,
         soul_ciphertext_hash,
         memories_ciphertext_hash,
         agent_config_ciphertext_hash
      }))

   The vault_hash SHOULD be anchored via the anchoring
   interface (Section 10).

8.5.  Recovery Flow

   1.  Owner presents the encryption key.

   2.  Platform computes keccak256(key) and verifies
       against the stored key hash.

   3.  If verification succeeds, encrypted vault contents
       are returned.

   4.  Owner decrypts locally using AES-256-GCM.

   Implementations MUST reject recovery attempts where the
   key hash does not match and MUST NOT provide any
   information about vault contents upon failure.

8.6.  Selective Disclosure

   Owners MAY reveal specific vault fields without
   exposing the entire vault.  Each field is encrypted
   with a separate IV under the same key.  Verifiers
   confirm the disclosed field matches the vault hash by
   recomputing the ciphertext hash.

8.7.  Passport Integration

   The passport MAY include a "memory_vault" field with
   vault_hash, encrypted_at, key_hash, items, and
   optional anchoring fields.


9.  Collaboration History

9.1.  Overview

   Collaboration History tracks multi-agent work,
   attribution, and trust signals derived from agents
   working together.

9.2.  Work Receipt Linking

   When multiple agents collaborate on a job, each agent
   MUST produce its own Work Receipt.  These receipts
   MUST reference a shared job_id.

9.3.  Attribution Records

   For multi-agent jobs, an attribution record MAY be
   attached to each Work Receipt:

      job_id:  Shared job identifier.

      collaborators:  Array with agent_id, role
         (lead/contributor/reviewer), contribution_pct,
         and receipt_hash.

   The sum of all contribution_pct values for a job MUST
   equal 100.

9.4.  Collaboration Graph

   The set of all collaboration records forms a graph
   where nodes are agents and edges represent co-work
   relationships weighted by frequency and recency.

9.5.  Knowledge Transfer

   Skills gained through collaboration SHOULD be recorded
   with origin "collaboration" and a reference to the
   job_id.  Knowledge transfer follows the heritage model
   with DNA mutation (Section 6.5).

9.6.  Trust Signals

   Collaboration produces trust signals:

      reliability:  Number [0, 1].

      quality:  Number [0, 1].

      timeliness:  Number [0, 1].

   Trust signals SHOULD be computed from verified Work
   Receipts only.  Implementations MUST NOT allow
   self-reported trust signals.


10.  Anchoring

10.1.  Overview

   Anchoring commits an artifact hash to an immutable
   ledger.  Anchoring is OPTIONAL but RECOMMENDED for
   high-assurance use cases.

10.2.  Provider Interface

   Any anchoring provider MUST implement:

      Commit(hash, metadata) -> AnchorReceipt

      Verify(hash) -> AnchorVerification

      Info() -> ProviderInfo

10.3.  Provider Types

   ethereum:  EVM-compatible blockchain.

   arweave:  Permanent storage network.

   transparency-log:  RFC 6962-style append-only log.

   noop:  Testing/development only.

10.4.  Commitment Flow

   1.  Compute the artifact hash.

   2.  Call Commit(hash, metadata).

   3.  Receive the AnchorReceipt.

   4.  Store the AnchorReceipt in the artifact's
       "anchoring" field.

10.5.  Anchor Receipt

   An AnchorReceipt contains:

      provider:  Provider type identifier.

      tx_hash:  Transaction or commitment identifier.

      block_number:  Block number (if applicable).

      timestamp:  ISO 8601 timestamp.

      chain_id:  Chain identifier.  OPTIONAL.

      metadata:  Provider-specific metadata.  OPTIONAL.

10.6.  Verification

   Verification MUST confirm:

   1.  The hash exists on the anchoring layer.

   2.  The tx_hash and block_number are valid.

   3.  The timestamp is consistent with the block
       timestamp.

   Implementations SHOULD verify directly against the
   anchoring layer rather than trusting cached results.


11.  Attestation Exchange

11.1.  Overview

   Attestation Exchange enables cross-platform
   verification of agent properties through signed
   third-party statements.

11.2.  Attestation Structure

   An attestation contains:

      type:  One of "identity", "capability", "behavior",
         "benchmark", "platform".

      issuer:  DID of the attesting entity.

      subject:  DID of the attested agent.

      issued_at:  ISO 8601 timestamp.

      expires_at:  ISO 8601 timestamp.  OPTIONAL.

      claims:  Attestation-specific claims object.

      proof:  Ed25519Signature2020 proof by the issuer.

11.3.  Cross-Platform Verification

   To verify an attestation from another platform:

   1.  Resolve the issuer's DID to obtain the public key.

   2.  Verify the Ed25519 signature over the canonical
       attestation (excluding the proof field).

   3.  Check that the attestation has not expired.

   4.  Optionally, verify the issuer against a trust
       registry.

11.4.  Trust Registry

   A Trust Registry is an OPTIONAL service maintaining a
   list of recognized attestation issuers.  Trust
   registries are informational; verification MUST NOT
   depend solely on registry membership.

11.5.  Attestation Lifecycle

   1.  Issuance -- Issuer creates and signs the
       attestation.

   2.  Presentation -- Agent includes it in its passport.

   3.  Verification -- Verifier checks signature, expiry,
       and issuer.

   4.  Revocation -- Issuer MAY revoke by publishing a
       signed revocation notice.


12.  Trust Levels and Blockchain Anchoring

12.1.  Overview

   APS operates at three trust levels with progressively
   stronger security guarantees.  Implementations MUST
   clearly declare which trust level they support.

12.2.  Trust Levels

12.2.1.  Level 1: APS Basic (No Blockchain Required)

   Provides standardized JSON format, Ed25519 signatures,
   Keccak-256 hash chains, and local verification.

   Limitations: self-reported timestamps, undetectable
   document replacement, cross-platform verification
   relies on signer trust.

   Suitable for: internal agent systems, development,
   single-organization deployments.

12.2.2.  Level 2: APS Anchored (Blockchain Required)

   Everything in Level 1, plus: immutable
   proof-of-existence, verifiable timestamps, tamper
   detection, batch anchoring via Merkle trees, and
   cross-organization verification.

   Cost: approximately $0.005-0.02 per transaction on L2
   chains.  Batch anchoring reduces costs by
   approximately 100x.

   Suitable for: production agent marketplaces,
   multi-organization deployments.

12.2.3.  Level 3: APS Full (Blockchain + On-Chain)

   Everything in Level 2, plus: on-chain attestations
   with revocation, heritage DAG anchoring, memory vault
   integrity proofs, on-chain governance, smart
   contract-based identity registry.

   Suitable for: high-assurance environments, regulated
   industries, financial/legal agent work.

12.3.  Feature-to-Level Mapping

   Level 1 features: Passport create/sign/verify, Work
   Receipt lifecycle, Security Envelope constraints,
   Snapshot hash chain.

   Level 2 adds: Verifiable timestamps, tamper detection,
   cross-platform verification, batch proofs.

   Level 3 adds: Heritage and lineage tracking,
   attestation exchange, memory vault integrity,
   benchmark governance, on-chain identity registry,
   revocable attestations.

12.4.  Why Blockchain

   Blockchain provides: no single point of trust,
   append-only by cryptographic proof, globally
   verifiable, censorship resistant, and time-stamping
   by consensus.

12.5.  Recommended Blockchain Architecture

   Primary chain: EVM-compatible Layer 2 with low cost,
   high throughput, full EVM compatibility, and L1
   security inheritance.

   Smart contract pattern: AgentIdentityRegistry with
   anchor, verify, and freeze functions.  Batch
   anchoring via Merkle root commitment.

   Cost optimization: batch anchoring every 5 minutes,
   off-chain Merkle proofs, on-chain hash-only
   commitment yields approximately 100x cost reduction.

12.6.  Degraded Mode

   Level 2 and 3 implementations SHOULD support graceful
   degradation when the blockchain provider is
   temporarily unavailable.  Unanchored artifacts MUST
   be queued for anchoring when connectivity resumes.


13.  Canonicalization and Hashing

13.1.  JSON Canonicalization Scheme (JCS)

   All hashing and signing operations use the JSON
   Canonicalization Scheme defined in [RFC8785].  Rules:

   1.  Object keys sorted lexicographically by Unicode
       code point.

   2.  No insignificant whitespace.

   3.  Strings MUST use UTF-8 encoding.

   4.  Numbers MUST use the shortest representation.

   5.  null, true, false serialized as literals.

   Implementations MUST use a conforming JCS
   implementation.

13.2.  Keccak-256

   All content hashes use Keccak-256 [KECCAK] (the
   pre-NIST variant, as used in Ethereum).  This is NOT
   NIST SHA-3 (FIPS 202).

   Input: UTF-8 bytes of canonical JSON.  Output: 32
   bytes as Hex256 ("0x" + 64 lowercase hex characters).

13.3.  Hash Computation

   The general hash computation:

      hash = "0x" + hex(keccak256(
                canonicalize(object \ {proof})))


14.  Cryptographic Operations

14.1.  Ed25519

   All signatures use Ed25519 [RFC8032].

   Public keys encoded using multibase z-base58btc as
   used in did:key (multicodec prefix 0xed01).

   Signature format: Ed25519Signature2020 with
   proofValue in multibase z-base58btc over the raw
   64-byte signature.

14.2.  AES-256-GCM

   Used for Memory Vault encryption:

   o  Key size: 256 bits.

   o  IV size: 96 bits, generated using CSPRNG.

   o  Tag size: 128 bits.

   o  Each operation MUST use a unique IV.

   o  IV reuse with the same key MUST NOT occur.

14.3.  Merkle Trees

   Batch proofs use binary Merkle trees:

      Leaf hash:
         keccak256(0x00 || receipt_hash_bytes)

      Internal node:
         keccak256(0x01 || min(left, right)
                        || max(left, right))

   Domain separation (0x00/0x01 prefixes) is REQUIRED
   for v1.1 implementations.  See Section 22 for
   advanced construction.

   Tree construction:

   1.  Compute leaf hashes for all receipts.

   2.  Sort leaf hashes lexicographically.

   3.  Build bottom-up, pairing adjacent leaves.

   4.  Odd leaves promoted without hashing.


15.  Conformance

15.1.  Conformance Levels

   Level 1 (Basic):  Valid JSON, correct hashes, valid
   signatures, correct @context and type fields.

   Level 2 (Enhanced):  Level 1 plus snapshot hash chain
   integrity, lifecycle ordering, envelope enforcement,
   frozen DNA respected, acyclic lineage DAG.

   Level 3 (Full):  Level 2 plus anchoring receipt
   verification, Merkle batch proof validation,
   attestation verification, trust signal derivation
   from verified Work Receipts only.

15.2.  Test Vectors

   Implementations MUST pass the test vectors defined in
   test-vectors.json (Appendix B).

15.3.  Test Vector Format

   Each test vector contains: name, description, input,
   expected_output, and optional notes.

15.4.  Conformance Assertion

   Implementations claiming conformance MUST declare
   their level:

      "This implementation conforms to APS v1.1 at
       Level [1|2|3]."


16.  Federation Protocol

   The Federation Protocol enables APS-compliant
   platforms to discover, verify, and exchange agent
   passports and attestations across organizational
   boundaries.  Federation discovery endpoints are
   published at well-known URIs and described by the
   federation-discovery.schema.json schema.

   A federation endpoint MUST support:

   o  Passport retrieval by agent DID.

   o  Attestation exchange.

   o  Cross-platform Work Receipt verification.

   o  Trust registry synchronization (OPTIONAL).

   Full federation protocol details are defined in the
   companion federation specification.


17.  MCP Security Profile

17.1.  Overview

   The MCP Security Profile defines how an APS agent
   declares, enforces, and audits security policies for
   Model Context Protocol [MCP] tool integrations.  It
   is embedded within the agent's Security Envelope
   (Section 5) as the "mcp_security" object.

17.2.  Tool Allowlist

   An agent passport MUST declare an explicit allowlist
   of MCP tools via the "mcp_tools_allowed" array.  Each
   entry MUST contain:

      server_hash:  Hex-encoded SHA-256 hash of the MCP
         server attestation bundle.

      tool_name:  Exact tool name as registered.

      version:  Semver version or range.

      data_classification_max:  Maximum data
         classification level.  Defaults to "public".

   An MCP runtime MUST reject any tool invocation not
   present in "mcp_tools_allowed".  The runtime MUST
   verify that the server_hash matches before dispatching
   the call.

17.3.  Data Classification

   Data classification levels (ordered):

   o  public -- No restrictions.

   o  internal -- Organization-internal data.

   o  confidential -- Restricted access required.

   o  secret -- Maximum protection required.

   The runtime MUST NOT send data to a tool whose
   "data_classification_max" is lower than the data's
   classification level.

17.4.  Server Attestation

   Each MCP server SHOULD publish a signed attestation
   bundle containing: server identity, supported tools
   with versions, security posture, and an Ed25519
   signature.

   The attestation bundle hash (SHA-256) is the value
   used in "server_hash" within the tool allowlist.

17.5.  Audit Trail

   All MCP tool invocations MUST be logged with:

   o  Timestamp of invocation.

   o  Tool name and version.

   o  Server hash.

   o  Data classification of inputs and outputs.

   o  Invocation result status.

   Audit logs SHOULD be anchored via the anchoring
   interface (Section 10) for tamper evidence.


18.  Model and Toolchain Provenance

18.1.  Motivation

   Supply-chain attacks against AI agents operate at
   multiple layers: compromised model weights, tampered
   runtimes, injected prompts, and disabled guardrails.
   Without cryptographic binding between a Work Receipt
   and the exact software stack that produced it,
   auditors cannot attribute outputs to a known-good
   configuration.

18.2.  Provenance Fields

   Work Receipts in v1.1 MUST include a "provenance"
   object with the following REQUIRED fields:

      model_hash:  Hex256.  Keccak-256 of the model
         weights or model card used during execution.

      runtime_hash:  Hex256.  Keccak-256 of the runtime
         binary or container image manifest.

      prompt_template_hash:  Hex256.  Keccak-256 of the
         prompt template(s) applied.

      guardrails_hash:  Hex256.  Keccak-256 of the
         guardrails/safety-filter configuration.

      toolchain_version:  Semver string identifying the
         SDK or toolchain version.

   OPTIONAL fields:

      pipeline_parent_receipt_id:  URI.  Links to a
         preceding Work Receipt in a multi-step pipeline.

      c2pa_manifest_hash:  Hex256.  Hash of a C2PA
         content credentials manifest.

18.3.  Pipeline Linking

   In complex agent pipelines, each stage MUST produce
   its own Work Receipt.  Receipts are linked via
   "pipeline_parent_receipt_id", forming a directed chain
   from first stage to final output.

   Verifiers SHOULD trace the full pipeline chain and
   verify each stage's provenance independently.

18.4.  C2PA Integration

   Implementations MAY embed C2PA [C2PA] content
   credentials manifests in Work Receipts for media
   outputs.  The "c2pa_manifest_hash" field provides
   a binding between the APS provenance record and the
   C2PA trust chain.


19.  Identity Continuity and Key Rotation

19.1.  Motivation

   Agent identity loss during upgrades is a critical
   pain point.  When an agent rotates keys -- whether
   due to routine hygiene, model upgrade, or compromise
   -- downstream verifiers lose the ability to link the
   new identity to prior reputation, work receipts, and
   attestations.

19.2.  Key Rotation Protocol

   Key rotation produces a KeyRotationEvent, a signed
   artifact containing:

      type:  MUST be "KeyRotationEvent".

      agent_did_old:  The current (outgoing) DID.

      agent_did_new:  The new (incoming) DID.

      reason:  One of "routine", "upgrade", "compromise".

      snapshot_version:  Current snapshot version.

      snapshot_hash:  Current snapshot hash.

      proof_old:  Ed25519Signature2020 by the old key.

      proof_new:  Ed25519Signature2020 by the new key.

   Both the old and new keys MUST sign the rotation
   event.  This dual-signature proves possession of both
   keys and creates a cryptographic continuity chain.

   For "compromise" rotations, the old key signature MAY
   be replaced by an owner attestation if the old key
   is no longer available.

19.3.  Model Upgrade Continuity

   When an agent's underlying model changes (e.g., from
   GPT-4 to GPT-5), the upgrade MUST be recorded as:

   1.  A DNA mutation (Section 6.5) with mutation_reason
       indicating the model change.

   2.  A KeyRotationEvent if the model change requires
       new key material.

   3.  A provenance record (Section 18) in subsequent
       Work Receipts reflecting the new model_hash.

   The agent's DID and reputation chain MUST survive
   model upgrades when key material is preserved or
   properly rotated.

19.4.  Compromise Recovery

   If an agent's private key is compromised:

   1.  The owner MUST issue a signed compromise notice
       using the owner's key (not the agent's key).

   2.  A new key pair MUST be generated.

   3.  A KeyRotationEvent with reason "compromise" MUST
       be created and anchored.

   4.  All attestations issued by the compromised key
       between compromise and detection SHOULD be
       reviewed and potentially revoked.

   5.  Platforms SHOULD implement a cooling-off period
       during which the rotated agent operates at a
       reduced trust tier.


20.  Execution Attestation

20.1.  Overview

   An Execution Attestation binds agent work products to
   verifiable execution environments.  It links a
   Security Envelope (Section 5) to a cryptographic
   measurement of the runtime, establishing not only
   what an agent produced but where and under what
   constraints the computation occurred.

   This addresses environment spoofing and replay attacks.

20.2.  Attestation Artifact

   An ExecutionAttestation is a signed JSON object:

      @context:  "https://agentpassport.org/v1.0"

      type:  MUST be "ExecutionAttestation".

      agent_id:  DID of the executing agent.

      receipt_id:  URI of the associated Work Receipt.

      envelope_hash:  Hex256 of the Security Envelope.

      measurement:  Runtime measurement object.

      timestamp:  ISO 8601 timestamp.

      proof:  Ed25519Signature2020 by the executor.

20.3.  Runtime Measurement

   The measurement object contains:

      platform:  One of "sgx", "sev-snp", "trustzone",
         "gvisor", "firecracker", "wasm", "container",
         "self-reported".

      platform_version:  Version string of the isolation
         technology.

      code_hash:  Hex256 of the agent code/binary.

      config_hash:  Hex256 of the runtime configuration.

      boot_hash:  Hex256 of boot measurements (for
         hardware TEEs).  OPTIONAL.

   Implementations SHOULD use hardware-backed attestation
   (SGX, SEV-SNP, TrustZone) where available.
   "self-reported" measurements provide no security
   guarantee and MUST be clearly marked.

20.4.  Verification Procedure

   1.  Verify the executor's Ed25519 signature.

   2.  Verify the envelope_hash matches the agent's
       declared Security Envelope.

   3.  Verify the receipt_id corresponds to a valid Work
       Receipt.

   4.  If hardware TEE: verify the platform attestation
       quote against the TEE vendor's root of trust.

   5.  Verify measurement hashes against known-good
       values (from a reference registry or the agent's
       provenance record).


21.  Anti-Sybil Reputation Framework

21.1.  Overview

   The Anti-Sybil Reputation Framework computes
   sybil-resistant reputation scores as a weighted,
   temporally-decaying aggregate of attestations with
   safeguards against manipulation.

21.2.  Reputation Score Formula

   An agent's reputation score R MUST be computed as:

      R = sum(w_i * r_i * d_i) / sum(w_i)

   Where:

      w_i:  Issuer weight for attestation i.

      r_i:  Rating value from attestation i, in [0, 1].

      d_i:  Temporal decay factor, computed as
         exp(-lambda * age_days).  The decay constant
         lambda SHOULD default to 0.01 (half-life of
         approximately 69 days).

21.3.  Issuer Weighting

   Issuer weight w_i is determined by:

   o  Issuer's own reputation score (recursive but
      bounded).

   o  Diversity of the issuer's attestation targets.

   o  Platform verification status.

   Self-attestation (issuer == subject) MUST receive
   weight 0.  Circular attestation chains (A attests B,
   B attests A) MUST be detected and down-weighted.

21.4.  Owner Diversity

   Reputation scores MUST account for owner diversity:

   o  If all attestations come from agents controlled by
      the same owner, a diversity penalty MUST be
      applied.

   o  Implementations MUST require attestations from at
      least 3 distinct owners for a reputation score
      above 0.5.

   o  Owner identity is derived from the genesis_owner
      field in the attesting agents' passports.

21.5.  Anomaly Detection

   Implementations SHOULD detect and flag:

   o  Burst patterns: many attestations in a short
      period.

   o  Reciprocal patterns: mutual attestation rings.

   o  Sudden reputation jumps without corresponding work
      history.

   Flagged agents SHOULD have their reputation score
   frozen pending manual review.

21.6.  Reputation Snapshots

   An agent's reputation MUST be captured in signed,
   timestamped snapshots conforming to
   reputation-summary.schema.json.  Reputation snapshots
   SHOULD be anchored for tamper evidence.


22.  Merkle Proofs and Advanced On-Chain Anchoring

22.1.  Introduction

   This section formalizes the Merkle tree construction
   algorithm, defines a multi-chain batch anchoring
   protocol, and specifies cross-chain verification
   procedures.  It supersedes the informational guidance
   in Section 14.3 and elevates domain-separated Merkle
   trees from RECOMMENDED to REQUIRED for all v1.1
   implementations.

22.2.  Merkle Tree Construction

   All v1.1 implementations MUST use domain-separated
   hashing:

      Leaf:  keccak256(0x00 || data)

      Node:  keccak256(0x01 || min(L,R) || max(L,R))

   Sibling sorting ensures canonical trees regardless
   of insertion order.

   Trees MUST be constructed bottom-up with sorted
   leaves.  Odd-count levels MUST promote the last node
   without hashing.

   Maximum tree depth: 20 (1,048,576 leaves).
   Implementations MUST reject trees exceeding this
   depth.

22.3.  Multi-Chain Batch Anchoring

   Implementations MAY anchor the same Merkle root to
   multiple chains for redundancy:

   o  Primary chain: fast finality, low cost (L2).

   o  Secondary chain: high security, slower finality
      (L1 or alternative L1).

   The AnchorReceipt MUST list all chain commitments.
   Verification succeeds if ANY listed chain confirms
   the anchor.

22.4.  Cross-Chain Verification

   To verify a cross-chain anchor:

   1.  Obtain the Merkle proof for the leaf.

   2.  Recompute the root from the proof.

   3.  Query each listed chain for the root commitment.

   4.  Accept if at least one chain confirms the root
       at a consistent timestamp.

   Implementations SHOULD cache chain query results
   with a TTL of no more than 5 minutes.


23.  Agent-to-Agent (A2A) Security and Workflows

23.1.  Overview

   This section defines how APS-compliant agents
   establish mutual trust, communicate securely,
   delegate capabilities, and maintain accountability
   in multi-agent workflows.

23.2.  Mutual Authentication

   Before any interaction, both agents MUST complete a
   mutual authentication handshake:

   1.  Agent A sends A2A-Hello with its DID and passport
       hash.

   2.  Agent B responds with A2A-HelloAck containing its
       DID and passport hash.

   3.  Both agents resolve each other's DID, retrieve
       the passport, and verify:

       a.  Passport signature validity.

       b.  Snapshot hash matches declared passport hash.

       c.  Trust tier meets minimum requirements.

       d.  Security Envelope is acceptable.

   4.  Both agents exchange a session nonce signed with
       their respective keys, establishing a shared
       session context.

23.3.  Capability Delegation

   An agent MAY delegate a subset of its capabilities
   to another agent via a signed DelegationToken:

      delegator:  DID of the delegating agent.

      delegate:  DID of the receiving agent.

      capabilities:  Array of delegated capability
         strings (MUST be a subset of the delegator's
         allowed capabilities).

      scope:  Constraint on delegation (job_id, time
         window, etc.).

      proof:  Ed25519Signature2020 by the delegator.

   Delegations MUST NOT exceed the delegator's own
   capability set.  Delegation chains (A delegates to B,
   B delegates to C) MUST be limited to a maximum depth
   of 3.

23.4.  Workflow Accountability

   In multi-agent workflows, each participating agent
   MUST produce its own Work Receipt.  The workflow
   coordinator (if any) MUST produce a summary Work
   Receipt linking all participant receipts via
   attribution records (Section 9.3).

   Workflow receipts SHOULD be batch-anchored using a
   single Merkle tree (Section 22) for efficiency.

23.5.  Error Handling

   If an agent fails during a workflow:

   o  The failing agent MUST produce a Work Receipt with
      a "submit" event containing an error description.

   o  Other agents in the workflow MUST NOT be held
      accountable for the failing agent's portion.

   o  The workflow coordinator SHOULD record the failure
      in its summary receipt.


24.  Security Considerations

24.1.  Key Management

   Agent identity is bound to an Ed25519 key pair.
   Compromise of the private key allows full
   impersonation.

   Implementations MUST:

   o  Store private keys in HSMs, secure enclaves, or
      equivalent protected storage where available.

   o  Never transmit private keys over unencrypted
      channels.

   o  Support key rotation via KeyRotationEvent
      (Section 19).

24.2.  Replay Attacks

   Signatures are bound to document content.  Mitigations
   include: timestamps and job identifiers in Work
   Receipts, snapshot versioning, and anchoring.
   Execution Attestations (Section 20) provide additional
   replay resistance through runtime measurements.

24.3.  Timing Attacks

   Implementations MUST use constant-time comparison for
   hash and signature verification.

24.4.  DID Resolution Attacks

   did:key embeds the public key directly, avoiding
   external resolution.  For did:web, implementations
   MUST validate results and SHOULD use DNSSEC-protected
   domains.

24.5.  Anchoring Provider Trust

   Anchoring provides tamper evidence, not tamper
   prevention.  The noop provider provides NO security
   guarantees and MUST NOT be used in production.
   Multi-chain anchoring (Section 22) reduces
   single-provider risk.

24.6.  Memory Vault Key Loss

   Vault encryption is irreversible without the owner's
   key.  The platform MUST NOT maintain recovery
   mechanisms.  Owners SHOULD maintain secure key backups.

24.7.  Cross-Platform Attestation Trust

   Attestations are only as trustworthy as their issuers.
   Expired and revoked attestations MUST be rejected.
   The anti-sybil framework (Section 21) provides
   resistance against attestation manipulation.

24.8.  Canonicalization Attacks

   Implementations MUST use conforming RFC 8785
   implementations.  Special attention is required for
   Unicode normalization and IEEE 754 numeric precision.

24.9.  Denial of Service

   Recommended limits:

   o  Maximum JSON nesting depth: 32 levels.

   o  Maximum document size: 1 MB.

   o  Maximum Merkle batch size: 65,536 receipts.

   o  Maximum Merkle tree depth: 20.

24.10.  MCP Tool Injection

   Without the MCP Security Profile (Section 17),
   malicious MCP servers could inject arbitrary tool
   responses.  Implementations MUST verify server_hash
   before dispatching calls and MUST enforce data
   classification boundaries.

24.11.  Model Supply-Chain Attacks

   Model provenance (Section 18) enables detection of
   compromised model weights, tampered runtimes, and
   injected prompts.  Implementations SHOULD maintain
   a registry of known-good model hashes and alert on
   deviations.

24.12.  Sybil Attacks

   The anti-sybil framework (Section 21) mitigates
   reputation manipulation through: issuer weighting,
   owner diversity requirements, temporal decay, and
   anomaly detection.  However, sufficiently resourced
   attackers with many distinct identities may still
   accumulate reputation.  Implementations SHOULD
   require proof-of-cost (e.g., blockchain transaction
   fees) for high-value attestations.

24.13.  Execution Environment Spoofing

   Self-reported execution measurements (Section 20)
   provide no security guarantee.  For high-assurance
   use cases, hardware TEE attestation (SGX, SEV-SNP)
   SHOULD be required.

24.14.  Capability Delegation Abuse

   Delegation chains (Section 23.3) are limited to depth
   3 to prevent laundering of capabilities through
   chains of agents.  Implementations MUST verify the
   full delegation chain before accepting delegated
   operations.

24.15.  Without Blockchain Anchoring

   Implementations at Trust Level 1 face: timestamp
   forgery, silent document replacement, heritage
   fabrication, attestation repudiation, and split-brain
   identity.  These risks are acceptable in trusted
   environments but critical in open ecosystems.


25.  IANA Considerations

25.1.  Media Types

25.1.1.  application/agent-passport+json

   Type name:  application

   Subtype name:  agent-passport+json

   Required parameters:  N/A

   Optional parameters:  N/A

   Encoding considerations:  binary (UTF-8 JSON)

   Security considerations:  See Section 24.

   Interoperability considerations:  See Section 15.

   Published specification:  This document.

   Applications that use this media type:  AI agent
      platforms, trust verification systems, agent
      registries.

   File extension(s):  .agent-passport.json

   Person & email address to contact:
      Cezary Grotowski <c.grotowski@gmail.com>

   Intended usage:  COMMON

   Author:  Cezary Grotowski

   Change controller:  IETF

25.1.2.  application/work-receipt+json

   Type name:  application

   Subtype name:  work-receipt+json

   Required parameters:  N/A

   Optional parameters:  N/A

   Encoding considerations:  binary (UTF-8 JSON)

   Security considerations:  See Section 24.

   Published specification:  This document.

   Applications that use this media type:  AI agent
      platforms, work verification systems.

   File extension(s):  .work-receipt.json

   Person & email address to contact:
      Cezary Grotowski <c.grotowski@gmail.com>

   Intended usage:  COMMON

   Author:  Cezary Grotowski

   Change controller:  IETF

25.1.3.  application/security-envelope+json

   Type name:  application

   Subtype name:  security-envelope+json

   Required parameters:  N/A

   Optional parameters:  N/A

   Encoding considerations:  binary (UTF-8 JSON)

   Security considerations:  See Section 24.

   Published specification:  This document.

   Applications that use this media type:  AI agent
      platforms, sandbox enforcement systems.

   File extension(s):  .security-envelope.json

   Person & email address to contact:
      Cezary Grotowski <c.grotowski@gmail.com>

   Intended usage:  COMMON

   Author:  Cezary Grotowski

   Change controller:  IETF

25.1.4.  application/execution-attestation+json

   Type name:  application

   Subtype name:  execution-attestation+json

   Required parameters:  N/A

   Optional parameters:  N/A

   Encoding considerations:  binary (UTF-8 JSON)

   Security considerations:  See Section 24.

   Published specification:  This document.

   Applications that use this media type:  AI agent
      platforms, TEE verification systems.

   File extension(s):  .execution-attestation.json

   Person & email address to contact:
      Cezary Grotowski <c.grotowski@gmail.com>

   Intended usage:  COMMON

   Author:  Cezary Grotowski

   Change controller:  IETF

25.2.  Context URLs

   The canonical context URL for APS v1.0:
      https://agentpassport.org/v1.0

   Sub-contexts:
      https://agentpassport.org/v1.0/dna
      https://agentpassport.org/v1.0/vault

25.3.  DID Methods

   This specification uses the did:key URI scheme as
   defined by W3C DID Core [W3C-DID].  No new DID
   method registration is requested.  Implementations
   MAY additionally support did:web.


26.  References

26.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs
              to Indicate Requirement Levels", BCP 14,
              RFC 2119, DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/rfc/rfc2119>.

   [RFC7517]  Jones, M., "JSON Web Key (JWK)", RFC 7517,
              DOI 10.17487/RFC7517, May 2015,
              <https://www.rfc-editor.org/rfc/rfc7517>.

   [RFC8032]  Josefsson, S. and I. Liusvaara,
              "Edwards-Curve Digital Signature Algorithm
              (EdDSA)", RFC 8032, DOI 10.17487/RFC8032,
              January 2017,
              <https://www.rfc-editor.org/rfc/rfc8032>.

   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman,
              "JSON Canonicalization Scheme (JCS)",
              RFC 8785, DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/rfc/rfc8785>.

   [RFC6962]  Laurie, B., Langley, A., and E. Kasper,
              "Certificate Transparency", RFC 6962,
              DOI 10.17487/RFC6962, June 2013,
              <https://www.rfc-editor.org/rfc/rfc6962>.

26.2.  Informative References

   [W3C-DID]  Sporny, M., Longley, D., Sabadello, M.,
              Reed, D., Steele, O., and C. Allen,
              "Decentralized Identifiers (DIDs) v1.0",
              W3C Recommendation, July 2022,
              <https://www.w3.org/TR/did-core/>.

   [W3C-VC]   Sporny, M., Longley, D., and D. Chadwick,
              "Verifiable Credentials Data Model v2.0",
              W3C Recommendation, 2024,
              <https://www.w3.org/TR/vc-data-model-2.0/>.

   [KECCAK]   Bertoni, G., Daemen, J., Peeters, M., and
              G. Van Assche, "The Keccak SHA-3
              submission", 2011,
              <https://keccak.team/keccak.html>.

   [MCP]      "Model Context Protocol", 2024,
              <https://modelcontextprotocol.io/>.

   [A2A]      "Agent-to-Agent Protocol", Google, 2025,
              <https://google.github.io/A2A/>.

   [C2PA]     "Coalition for Content Provenance and
              Authenticity", C2PA Specification, 2024,
              <https://c2pa.org/specifications/>.

   [ERC-8004] "ERC-8004: Agent Identity", Ethereum
              Improvement Proposals, 2024,
              <https://eips.ethereum.org/EIPS/eip-8004>.


Appendix A.  JSON Schemas

   The following JSON Schema files define the normative
   structure of APS artifacts:

   agent-passport.schema.json      Agent Passport
   work-receipt.schema.json        Work Receipt
   security-envelope.schema.json   Security Envelope
   dna.schema.json                 Agent DNA (standalone)
   memory-vault.schema.json        Memory Vault
   anchoring.schema.json           Anchor Receipt
   bundle.schema.json              Passport Bundle
   execution-attestation.schema.json  Execution Attestation
   mcp-security-profile.schema.json  MCP Security Profile
   model-provenance-extension.schema.json  Model Provenance
   reputation-summary.schema.json  Reputation Summary
   federation-discovery.schema.json  Federation Discovery

   Schemas are available at:
   https://agentpassport.org/v1.0/schemas/

   And in the specification repository under spec/.


Appendix B.  Test Vectors

   Normative test vectors are defined in
   spec/test-vectors.json in the APS repository.

   Test vectors cover:

   1.  Canonicalization.
   2.  Hashing (Keccak-256).
   3.  Signing (Ed25519).
   4.  Verification.
   5.  Merkle tree construction and proofs.
   6.  Snapshot hash chain.
   7.  Key rotation continuity.
   8.  Reputation score computation.

   Implementations claiming any conformance level MUST
   pass all test vectors for that level.


Appendix C.  Implementation Notes

   Reference implementations are available in three
   languages:

   Go SDK (go/ directory):  Targets Go 1.21+.  Packages:
   aps/canonical, aps/crypto, aps/merkle, aps/passport,
   aps/receipt, aps/envelope, aps/anchor.

   Python SDK (python/ directory):  Targets Python 3.10+.
   Available via PyPI as "agent-passport-standard".

   TypeScript SDK (typescript/ directory):  Targets
   ES2022+ and Node.js 18+.  Published to npm as
   "@agent-passport/sdk".

   Common pitfalls:

   1.  Using SHA-3 instead of Keccak-256.
   2.  Non-canonical JSON serialization.
   3.  Mutable genesis_owner.
   4.  IV reuse in AES-256-GCM.
   5.  Variable-time hash comparison.
   6.  Missing domain separation in Merkle trees.


Authors' Addresses

   Cezary Grotowski
   ClawBotDen

   Email: c.grotowski@gmail.com
   URI:   https://agentpassport.org
