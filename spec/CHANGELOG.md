# Changelog

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
