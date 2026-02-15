# Changelog

## v0.3.0 — 2026-02-16

### New Schemas
- **`bundle.schema.json`** — AgentPassportBundle schema for portable export/import of agent passports with associated work receipts, attestations, reputation summaries, and anchoring proofs. Context: `https://agentpassport.org/v0.2/bundle`.
- **`reputation-summary.schema.json`** — Portable Reputation Summary schema aggregating per-agent performance metrics (jobs completed/verified, quality/timeliness scores, trust tier, benchmark scores) over a time period. Context: `https://agentpassport.org/v0.2/reputation`.
- **`federation-discovery.schema.json`** — Well-Known Federation Discovery document (`/.well-known/aps-federation`) enabling platforms to advertise APS endpoints, supported DID methods, and blockchain anchoring configuration. Type: `APSFederationDiscovery`.

### Notes
- All new schemas use JSON Schema 2020-12 with consistent `$id` URLs under `agentpassport.org/schemas/`.
- Common `$defs` (Hex256, DID, Timestamp, Proof) are replicated for standalone validation; DID pattern extended to support both `did:key` and `did:web`.
- Bundle schema references `agent-passport.schema.json`, `work-receipt.schema.json`, and `reputation-summary.schema.json` via `$ref`.

## v1.0.1 — 2026-02-15

### Trust Levels & Blockchain Anchoring Requirement
- **Section 14 (SPECIFICATION.md) / Section 12 (RFC draft): Trust Levels & Blockchain Anchoring Requirement** — Defined three trust levels (Basic, Anchored, Full) with progressively stronger security guarantees. Blockchain anchoring is now REQUIRED for heritage tracking, cross-platform attestation exchange, memory vault integrity proofs, and on-chain identity registry (Level 3). Level 2 (Anchored) requires blockchain for verifiable timestamps, tamper detection, and cross-platform verification.
- Added Feature-to-Level Mapping table specifying minimum trust level for each APS feature.
- Added recommended EVM-compatible L2 blockchain architecture with smart contract patterns and cost optimization guidance.
- Added Degraded Mode requirements for Level 2/3 implementations.
- **Section 15 (SPECIFICATION.md) / Section 16.10 (RFC draft): Security Considerations — Without Blockchain Anchoring** — New subsection documenting risks of operating at Trust Level 1: timestamp forgery, silent document replacement, heritage fabrication, attestation repudiation, and split-brain identity.
- Updated README.md with Trust Levels summary table.

## v1.0.0 — 2026-02-15

### RFC-Style Internet-Draft
- Reformatted entire specification as Internet-Draft (`draft-grotowski-aps-01`).
- Added YAML front matter with RFC metadata, normative/informative references.
- Added Abstract, Status of This Memo, and Table of Contents per RFC conventions.

### New Sections
- **Section 11: Attestation Exchange** — Cross-platform attestation structure, verification flow, trust registry interface, attestation lifecycle (issuance, presentation, verification, revocation).
- **Section 12: Canonicalization and Hashing** — Dedicated section expanding RFC 8785 requirements, Keccak-256 specification (explicit NOT SHA-3), hash computation formula.
- **Section 13: Cryptographic Operations** — Ed25519 key encoding and signature format, AES-256-GCM parameters for Memory Vault, Merkle tree construction with domain separation (0x00 leaf prefix, 0x01 node prefix).
- **Section 14: Conformance** — Three conformance levels (Basic, Enhanced, Full) with explicit requirements per level. Test vector format. Conformance assertion template.
- **Section 15: Security Considerations** — Comprehensive threat model: key management, replay attacks, timing attacks, DID resolution attacks, anchoring provider trust, memory vault key loss, cross-platform attestation trust, canonicalization attacks, denial of service.
- **Section 16: IANA Considerations** — Media type registrations for `application/agent-passport+json`, `application/work-receipt+json`, `application/security-envelope+json`. Context URL `https://agentpassport.org/v1.0`.
- **Section 17: References** — Normative (RFC 2119, RFC 8032, RFC 8785, RFC 6962) and Informative (W3C DID Core, W3C VC Data Model, Keccak, MCP, A2A).
- **Appendix A: JSON Schemas** — Complete schema file listing.
- **Appendix B: Test Vectors** — Reference to test-vectors.json with coverage categories.
- **Appendix C: Implementation Notes** — Go, Python, TypeScript SDK structure and common pitfalls.

### Expanded Sections (from v0.2)
- **Introduction** — Added problem statement, motivation (4 requirements), scope (in/out), relationship to other standards table.
- **Terminology** — Expanded to RFC 2119 definition list format with all domain terms.
- **Agent Passport** — ABNF-like field specification, detailed field definitions (3.3.1–3.3.10), immutability rules, snapshot structure, proof computation.
- **Work Receipt** — Full document structure, event type table with signer roles, evidence fields, snapshot binding, batch proof with batch_size.
- **Security Envelope** — Capability string format (dot-separated hierarchical), sandbox runtime options expanded (added `container`), network allow-list detail, trust tier table.
- **Agent DNA** — Skill origin field (`innate`, `learned`, `collaboration`, `inherited`).
- **Lineage & Heritage** — Parent entry structure, generation computation for merge agents, cycle detection requirement.
- **Memory Vault** — CSPRNG requirement for IV generation, explicit rejection behavior on failed key verification.
- **Anchoring** — Commitment flow (4 steps), anchor receipt structure, verification requirements (3 checks).
- **Merkle Trees** — Domain separation prefixes (0x00 for leaves, 0x01 for nodes), sorted sibling concatenation, odd-leaf promotion rule.

### Breaking Changes from v0.2
- `@context` changed from `"https://agentpassport.org/v0.1"` to `"https://agentpassport.org/v1.0"`.
- `spec_version` changed from `"0.1.0"` / `"0.2.0"` to `"1.0.0"`.
- Merkle tree leaf/node hashing now uses domain separation prefixes.

### New Files
- `spec/draft-grotowski-aps-v1.md` — Internet-Draft document.
- `docs/IMPLEMENTATION-GUIDE.md` — Practical implementor guide with migration notes.

## v0.2.0 — 2026-02-14

- **Section 9: Agent DNA** — Canonical DNA representation (skills, soul, policies → keccak256 hash), frozen DNA, DNA mutation via version bump.
- **Section 10: Lineage & Heritage** — Extended lineage with heritage score formula, bot genealogy DAG, trait attribution, founding cohorts.
- **Section 11: Memory Vault** — AES-256-GCM encrypted agent state backup, owner-held keys, selective disclosure, on-chain vault hash anchoring.
- **Section 12: Collaboration History** — Multi-agent work attribution, collaboration graph, knowledge transfer, trust signals (reliability, quality, timeliness).
- Added `dna`, `memory_vault`, and `collaboration` fields to `agent-passport.schema.json`.
- Added extended lineage fields: `heritage_score`, `founding_cohort`, `traits_inherited`.
- New schema: `dna.schema.json`.
- New schema: `memory-vault.schema.json`.
- New example: `example-dna.json`.
- New example: `example-recovery.json`.
- All changes are additive; v0.1 passports remain valid.

## v0.1.0 — 2026-02-14

- Initial release of Agent Passport Standard (v0.1.x draft).
- Added three core artifacts:
  - `AgentPassport`
  - `WorkReceipt`
  - `SecurityEnvelope`
- Added JSON schemas and test vectors for conformance checks.
- Added Go SDK reference implementation:
  - canonical JSON
  - keccak256 hashing
  - Ed25519 signing/verification
  - merkle tree and verification utilities
  - compatibility and anchoring abstractions
- Added CLI for artifact validation:
  - `passport-cli verify`
  - `passport-cli receipt verify`
  - `passport-cli envelope validate`
- Added interoperability example folders for MCP and A2A integration.
