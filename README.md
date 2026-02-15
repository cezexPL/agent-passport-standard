<p align="center">
  <h1 align="center">🛂 Agent Passport Standard (APS)</h1>
  <p align="center">
    <strong>Open standard for verifiable AI agent identity, provenance, and trust.</strong>
  </p>
  <p align="center">
    <a href="./spec/SPECIFICATION.md"><img src="https://img.shields.io/badge/spec-v0.2.0-blue?style=flat-square" alt="Spec v0.2.0"></a>
    <a href="./go"><img src="https://img.shields.io/badge/Go_SDK-1.22-00ADD8?style=flat-square&logo=go" alt="Go 1.22"></a>
    <a href="./spec"><img src="https://img.shields.io/badge/schemas-JSON_Schema-green?style=flat-square" alt="JSON Schema"></a>
    <a href="./go/conformance"><img src="https://img.shields.io/badge/conformance-passing-brightgreen?style=flat-square" alt="Conformance"></a>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue?style=flat-square" alt="License"></a>
  </p>
</p>

---

## The Problem

AI agents are proliferating across every domain — coding, operations, research, infrastructure. But there's no standard way to answer three fundamental questions:

1. **Who is this agent?** — Identity, lineage, capabilities
2. **What has it done?** — Verifiable, auditable work history
3. **What can it do?** — Execution constraints, trust boundaries

MCP handles tool integration. A2A handles agent communication. AGENTS.md describes repo behavior. **None of them address agent identity, work verification, or trust.**

Agent Passport fills that gap.

---

## What Is Agent Passport?

Agent Passport Standard defines **cryptographically verifiable artifacts** for AI agents operating in open ecosystems:

### Core Artifacts (v0.1+)

| Artifact | Purpose | Schema |
|----------|---------|--------|
| **🛂 Agent Passport** | Identity, skills, lineage, trust signals | [`agent-passport.schema.json`](./spec/agent-passport.schema.json) |
| **📋 Work Receipt** | Verifiable proof of completed work | [`work-receipt.schema.json`](./spec/work-receipt.schema.json) |
| **🔒 Security Envelope** | Sandbox constraints, capability boundaries | [`security-envelope.schema.json`](./spec/security-envelope.schema.json) |

### Extended Modules (v0.2+)

| Module | Purpose | Schema |
|--------|---------|--------|
| **🧬 Agent DNA** | Immutable genetic code (skills + soul + policies) | [`dna.schema.json`](./spec/dna.schema.json) |
| **🌳 Lineage & Heritage** | Derivation history, genealogy DAG, heritage scoring | Passport `lineage` field |
| **🔐 Memory Vault** | AES-256-GCM encrypted state backup, selective disclosure | [`memory-vault.schema.json`](./spec/memory-vault.schema.json) |
| **🤝 Collaboration History** | Multi-agent attribution, trust signals | Work Receipt extensions |

---

## Design Principles

- **Vendor-neutral** — No platform lock-in. Works with any agent framework.
- **Cryptographically verifiable** — Ed25519 signatures + keccak-256 hashes + RFC 8785 canonical JSON.
- **Privacy-first** — Owner controls all data. Memory Vault uses client-side encryption. Platform never holds raw keys.
- **Immutable lineage** — `genesis_owner` never changes. DNA mutations create new versions, preserving the full hash chain.
- **Pluggable anchoring** — Optional on-chain commitment (Ethereum/Base, Arweave, transparency logs) via provider interface.

---

## Quick Start

### Validate artifacts with the CLI

```bash
cd go && go build ./cmd/passport-cli

# Verify a passport
./passport-cli verify ../examples/example-passport.json

# Verify a work receipt  
./passport-cli receipt verify ../examples/example-receipt.json

# Validate a security envelope
./passport-cli envelope validate ../examples/example-envelope.json
```

### Use the Go SDK

```go
import (
    "github.com/cezexPL/agent-passport-standard/go/passport"
    "github.com/cezexPL/agent-passport-standard/go/crypto"
)

// Create a new agent passport
pub, priv, _ := crypto.GenerateKeyPair()
p := passport.New("did:key:z6Mk...", pub)

// Set skills and soul
p.Snapshot.Skills = []passport.Skill{{Name: "go-backend", Version: "1.0"}}
p.Snapshot.Soul = passport.Soul{Personality: "Focused, reliable"}

// Compute DNA hash and sign
p.Snapshot.Hash = crypto.Keccak256Canonical(p.Snapshot.Skills, p.Snapshot.Soul, p.Snapshot.Policies)
p.Sign(priv)

// Verify
valid := p.Verify()
```

### Run the conformance suite

```bash
cd go
go test ./...
go test ./conformance -v
```

---

## Specification

📖 **[Full Specification (v0.2)](./spec/SPECIFICATION.md)** — 12 sections covering all artifacts, cryptographic primitives, anchoring, DNA, lineage, memory vault, and collaboration history.

### Key Sections

| § | Topic | Summary |
|---|-------|---------|
| 1 | Agent Passport | Identity binding, snapshot versioning, hash chains |
| 2 | Work Receipt | Job lifecycle (claim → submit → verify → payout), evidence, batch proofs |
| 3 | Security Envelope | Capabilities, sandbox (gVisor/Firecracker/WASM), trust tiers |
| 4 | Anchoring | Pluggable interface for on-chain commitment (Ethereum, Arweave, etc.) |
| 5 | Canonicalization | RFC 8785 (JCS) for deterministic serialization |
| 6 | Cryptographic Primitives | Ed25519 signatures, keccak-256, Merkle trees |
| 7 | Interoperability | MCP, A2A, AGENTS.md compatibility |
| 8 | Conformance | Three levels (Basic → Enhanced → Full), test vectors |
| 9 | Agent DNA | Immutable genetic code, frozen DNA, mutation rules |
| 10 | Lineage & Heritage | Genealogy DAG, heritage scoring, founding cohorts |
| 11 | Memory Vault | Client-side AES-256-GCM, selective disclosure, recovery |
| 12 | Collaboration History | Multi-agent attribution, trust signals, knowledge transfer |

---

## Repository Structure

```
agent-passport-standard/
├── spec/                          # Specification & schemas
│   ├── SPECIFICATION.md           # Full spec (v0.2)
│   ├── CHANGELOG.md               # Version history
│   ├── agent-passport.schema.json # Passport JSON Schema
│   ├── work-receipt.schema.json   # Work Receipt JSON Schema
│   ├── security-envelope.schema.json
│   ├── dna.schema.json            # Agent DNA JSON Schema
│   ├── memory-vault.schema.json   # Memory Vault JSON Schema
│   ├── anchoring.schema.json      # Anchoring receipt schema
│   └── test-vectors.json          # Conformance test vectors
├── go/                            # Reference Go SDK
│   ├── passport/                  # Passport create/verify
│   ├── receipt/                   # Work Receipt handling
│   ├── envelope/                  # Security Envelope validation
│   ├── crypto/                    # Ed25519, keccak-256, Merkle, canonical JSON
│   ├── anchor/                    # Anchoring provider interface + noop
│   ├── compat/                    # Agent Skills format converter
│   ├── conformance/               # Conformance suite runner
│   └── cmd/passport-cli/          # CLI validator tool
├── examples/                      # Example artifacts
│   ├── example-passport.json
│   ├── example-receipt.json
│   ├── example-envelope.json
│   ├── example-dna.json
│   ├── example-recovery.json
│   ├── mcp-integration/           # MCP interop example
│   └── a2a-exchange/              # A2A interop example
├── CONTRIBUTING.md
└── LICENSE                        # CC BY 4.0 (spec) + MIT (code)
```

---

## How It Fits In the AI Agent Ecosystem

```
┌─────────────────────────────────────────────────────────┐
│                   AI Agent Standards                     │
├─────────────┬─────────────┬─────────────┬───────────────┤
│   MCP       │    A2A      │  AGENTS.md  │  Agent        │
│   (Tools)   │  (Comms)    │  (Repos)    │  Passport     │
│             │             │             │  (Identity)   │
│  "What can  │ "How agents │ "How to     │ "Who is this  │
│   I use?"   │  talk"      │  behave in  │  agent? What  │
│             │             │  this repo" │  has it done?" │
└─────────────┴─────────────┴─────────────┴───────────────┘
```

Agent Passport is **complementary** to MCP, A2A, and AGENTS.md — not a replacement. It provides the identity and trust layer that ties them all together.

---

## Interoperability

| Standard | Integration |
|----------|------------|
| **MCP** | Passport skills align with MCP tool capabilities. Agents declare MCP-compatible tools in their DNA. |
| **A2A** | Passport snapshots exchanged during A2A capability negotiation. Work receipts serve as trust signals. |
| **AGENTS.md** | Passport `soul.constraints` MAY reference AGENTS.md compliance. |
| **DID** | Agent identity uses `did:key` (W3C DID Core). Supports any DID method. |
| **W3C VC** | Attestations follow W3C Verifiable Credentials data model. |

See [`examples/mcp-integration/`](./examples/mcp-integration/) and [`examples/a2a-exchange/`](./examples/a2a-exchange/) for runnable code.

---

## Cryptographic Foundation

| Primitive | Standard | Usage |
|-----------|----------|-------|
| **Ed25519** | RFC 8032 | All document signatures |
| **Keccak-256** | Ethereum variant | Content hashing (NOT NIST SHA-3) |
| **JCS** | RFC 8785 | Canonical JSON serialization |
| **Merkle Trees** | — | Batch proof for work receipts |
| **AES-256-GCM** | — | Memory Vault encryption |

---

## Conformance

Three conformance levels ensure implementations are interoperable:

| Level | Requirements |
|-------|-------------|
| **Basic** | Valid JSON matching schema. Correct hashes. Valid Ed25519 signature. |
| **Enhanced** | + Snapshot hash chain integrity. Work receipt lifecycle. Security envelope enforcement. |
| **Full** | + Anchoring verification. Merkle batch proofs. Benchmark attestation verification. |

Run the conformance suite:

```bash
cd go && go test ./conformance -v
```

---

## Roadmap

- [x] **v0.1** — Core: Passport, Work Receipt, Security Envelope, Anchoring
- [x] **v0.2** — Extended: Agent DNA, Lineage & Heritage, Memory Vault, Collaboration History
- [x] **v0.3** — SDK: Python SDK, TypeScript/Deno SDK, CI/CD, Cross-SDK Conformance
- [ ] **v0.4** — Advanced: Cross-platform attestation exchange, multi-chain anchoring
- [ ] **v1.0** — Stable: RFC submission, formal security audit

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

- **Spec changes** — Open an RFC issue first
- **SDK improvements** — PRs welcome, include tests
- **New language SDKs** — Open an issue to coordinate
- **Examples** — Always appreciated

---

## Author

**Cezary Grotowski** — [c.grotowski@gmail.com](mailto:c.grotowski@gmail.com)  
GitHub: [@cezexPL](https://github.com/cezexPL)

---

## License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](./LICENSE) file for details.

You are free to use, modify, and distribute this standard in both commercial and non-commercial projects.

---

<p align="center">
  <sub>Created by <a href="https://github.com/cezexPL">Cezary Grotowski</a> · Reference implementation: <a href="https://clawbotden.com">ClawBotDen</a></sub>
</p>
