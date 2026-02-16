<p align="center">
  <img src="assets/aps-cover.png" alt="Agent Passport Standard — APS Lobster" width="720" />
</p>

<p align="center">
  <h1 align="center">🛂 Agent Passport Standard (APS)</h1>
  <p align="center">
    <strong>Open standard for verifiable AI agent identity, provenance, and trust.</strong>
  </p>
  <p align="center">
    <a href="./spec/SPECIFICATION.md"><img src="https://img.shields.io/badge/spec-v1.0.0-blue?style=flat-square" alt="Spec v1.0.0"></a>
    <a href="./go"><img src="https://img.shields.io/badge/Go_SDK-1.22-00ADD8?style=flat-square&logo=go" alt="Go 1.22"></a>
    <a href="./python"><img src="https://img.shields.io/badge/Python_SDK-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
    <a href="./typescript"><img src="https://img.shields.io/badge/TypeScript_SDK-5.7+-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript 5.7+"></a>
    <a href="https://pypi.org/project/aps-sdk/"><img src="https://img.shields.io/badge/PyPI-aps--sdk-blue?style=flat-square&logo=pypi" alt="PyPI"></a>
    <a href="https://www.npmjs.com/package/aps-sdk"><img src="https://img.shields.io/badge/npm-aps--sdk-red?style=flat-square&logo=npm" alt="npm"></a>
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

### Core Artifacts

| Artifact | Purpose | Schema |
|----------|---------|--------|
| **🛂 Agent Passport** | Identity, skills, lineage, trust signals | [`agent-passport.schema.json`](./spec/agent-passport.schema.json) |
| **📋 Work Receipt** | Verifiable proof of completed work | [`work-receipt.schema.json`](./spec/work-receipt.schema.json) |
| **🔒 Security Envelope** | Sandbox constraints, capability boundaries | [`security-envelope.schema.json`](./spec/security-envelope.schema.json) |

### Extended Modules

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

## Trust Levels

APS operates at three trust levels with progressively stronger guarantees:

| Level | Blockchain? | Guarantees |
|-------|------------|------------|
| **Basic** | No | Format + signatures. Trust the signer. |
| **Anchored** | Yes | + Immutability, verifiable timestamps, tamper detection |
| **Full** | Yes + on-chain | + Heritage, attestation exchange, governance, identity registry |

> **Without blockchain, APS is a format standard. With blockchain, APS is a security standard.**

We strongly recommend Level 2 (Anchored) for any production deployment.
Level 3 (Full) is recommended for agent marketplaces and multi-organization ecosystems.

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

### Cross-Platform Portability

Agents can export their identity, work history, and reputation as a signed bundle — and import it on any other APS-compatible platform:

```bash
# Inspect a bundle exported from another platform
./passport-cli bundle inspect examples/example-bundle.json

# Verify a bundle (checks bundle signature + passport integrity)
./passport-cli bundle verify examples/example-bundle.json
```

```go
// Export: create a portable bundle with reputation
bundle := bundle.NewBundle(passport,
    bundle.WithReceipts(workReceipts),
    bundle.WithAttestations(attestations),
    bundle.WithReputation(reputationSummary),
    bundle.WithPlatformDID("did:web:clawbotden.com"),
)
bundle.Sign(platformPrivateKey)
data, _ := bundle.JSON()

// Import: verify and accept an agent from another platform
imported, _ := bundle.FromJSON(data)
report, _ := imported.VerifyAll(senderPublicKey)
// report.BundleValid, report.PassportValid, report.ReceiptsValid...
```

**DID Resolution** — resolve agent identity across platforms:

```go
resolver := did.DefaultResolver() // did:key + did:web
doc, _ := resolver.Resolve("did:web:clawbotden.com:bots:TARS-001")
pubKey, _ := did.ExtractPublicKey(doc)
```

**Platform Discovery** — any APS platform publishes:
```
GET /.well-known/agent-passport-standard → federation endpoints
GET /.well-known/did.json               → platform DID document
GET /bots/{name}/did.json               → per-agent DID document
```

### Install the SDK

**Go:**
```bash
go get github.com/cezexPL/agent-passport-standard/go@v1.0.0
```

**Python:**
```bash
pip install aps-sdk
```

**TypeScript:**
```bash
npm install agent-passport-sdk
```

### Use the Go SDK

```go
import (
    "github.com/cezexPL/agent-passport-standard/go/passport"
    "github.com/cezexPL/agent-passport-standard/go/crypto"
)

pub, priv, _ := crypto.GenerateKeyPair()
p, _ := passport.New(passport.Config{
    ID:       "did:key:z6MkAgent123",
    PublicKey: hex.EncodeToString(pub),
    OwnerDID: "did:key:z6MkOwner456",
    Skills:   []passport.Skill{{Name: "go-backend", Version: "1.0", Description: "Go dev", Capabilities: []string{"code_write"}, Hash: "0x..."}},
    Soul:     passport.Soul{Personality: "Focused", WorkStyle: "Systematic", Constraints: []string{}, Hash: "0x..."},
    Policies: passport.Policies{PolicySetHash: "0x...", Summary: []string{"read-only"}},
    Lineage:  passport.Lineage{Kind: "original", Parents: []string{}, Generation: 0},
})
_ = p.Sign(priv)
ok, _ := p.Verify(pub) // true
```

### Use the Python SDK

```python
from aps import AgentPassport, PassportConfig, Skill, Soul, Policies, Lineage
from aps.crypto import generate_key_pair

pub, priv = generate_key_pair()
p = AgentPassport.new(PassportConfig(
    id="did:key:z6MkAgent123", public_key=pub_hex, owner_did="did:key:z6MkOwner456",
    skills=[Skill("code-review", "1.0", "Review", ["code_review"], "0x...")],
    soul=Soul("Thorough", "Sequential", [], "0x..."),
    policies=Policies("0x...", ["read-only"]),
    lineage=Lineage("original", [], 0),
))
p.sign(priv)
assert p.verify(pub)
```

### Use the TypeScript SDK

```typescript
import { AgentPassport, generateKeyPair } from 'aps-sdk';
import { bytesToHex } from '@noble/hashes/utils';

const { publicKey, privateKey } = generateKeyPair();
const p = await AgentPassport.create({
  id: 'did:key:z6MkAgent123', publicKey: bytesToHex(publicKey),
  ownerDID: 'did:key:z6MkOwner456',
  skills: [{ name: 'ts-backend', version: '1.0', description: 'TS dev', capabilities: ['code_write'], hash: '0x...' }],
  soul: { personality: 'Focused', work_style: 'Systematic', constraints: [], hash: '0x...', frozen: false },
  policies: { policy_set_hash: '0x...', summary: ['read-only'] },
  lineage: { kind: 'original', parents: [], generation: 0 },
});
await p.sign(privateKey);
console.log(await p.verify(publicKey)); // true
```

### Run the conformance suite

```bash
cd go && go test ./...
cd python && python3 -m pytest tests/ -v
cd typescript && npx vitest run
```

---

## Specification

📖 **[Full Specification (v1.0)](./spec/SPECIFICATION.md)** — 12 sections covering all artifacts, cryptographic primitives, anchoring, DNA, lineage, memory vault, and collaboration history.

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
│   ├── SPECIFICATION.md           # Full spec (v0.3) — 16 sections incl. Federation Protocol
│   ├── CHANGELOG.md               # Version history
│   ├── agent-passport.schema.json # Passport JSON Schema
│   ├── work-receipt.schema.json   # Work Receipt JSON Schema
│   ├── security-envelope.schema.json
│   ├── dna.schema.json            # Agent DNA JSON Schema
│   ├── memory-vault.schema.json   # Memory Vault JSON Schema
│   ├── anchoring.schema.json      # Anchoring receipt schema
│   ├── bundle.schema.json         # Cross-platform export bundle schema
│   ├── reputation-summary.schema.json # Portable reputation schema
│   ├── federation-discovery.schema.json # Platform discovery schema
│   ├── test-vectors.json          # Conformance test vectors
│   ├── mcp-security-profile.md    # §17 MCP Security Profile (v1.1)
│   ├── model-provenance.md        # §18 Model & Toolchain Provenance (v1.1)
│   ├── identity-continuity.md     # §19 Identity Continuity & Key Rotation (v1.1)
│   ├── execution-attestation.md   # §20 Execution Attestation (v1.1)
│   ├── anti-sybil-reputation.md   # §21 Anti-Sybil Reputation Framework (v1.1)
│   ├── merkle-anchoring.md        # §22 Merkle Proofs & On-Chain Anchoring (v1.1)
│   └── a2a-security.md            # §23 A2A Security & Cross-Agent Trust (v1.1)
├── go/                            # Go SDK (github.com/cezexPL/agent-passport-standard/go)
│   ├── passport/                  # Passport create/verify
│   ├── receipt/                   # Work Receipt handling
│   ├── envelope/                  # Security Envelope validation
│   ├── bundle/                    # Cross-platform export/import bundles
│   ├── did/                       # DID resolution (did:key, did:web, multi-resolver)
│   ├── attestation/               # W3C VC attestations, persistent registry, revocation
│   ├── crypto/                    # Ed25519, keccak-256, Merkle, canonical JSON
│   ├── anchor/                    # Ethereum + Arweave + NoOp providers
│   ├── compat/                    # Agent Skills format converter
│   ├── conformance/               # Conformance suite runner
│   ├── cmd/passport-cli/          # CLI validator tool (passport, receipt, envelope, bundle)
│   └── API.md                     # Go API documentation
├── python/                        # Python SDK (aps-sdk on PyPI)
│   ├── aps/                       # Core: passport, receipt, envelope, bundle, did, reputation
│   ├── tests/                     # Test suite + benchmarks
│   └── API.md                     # Python API documentation
├── typescript/                    # TypeScript SDK (aps-sdk on npm)
│   ├── src/                       # Core: passport, receipt, envelope, bundle, did, reputation
│   ├── tests/                     # Test suite + benchmarks
│   └── API.md                     # TypeScript API documentation
├── examples/                      # Example artifacts
│   ├── example-passport.json
│   ├── example-receipt.json
│   ├── example-envelope.json
│   ├── example-dna.json
│   ├── example-bundle.json        # Cross-platform export bundle example
│   ├── example-recovery.json
│   ├── mcp-integration/           # MCP interop example
│   └── a2a-exchange/              # A2A interop example
├── CONTRIBUTING.md
└── LICENSE                        # Apache 2.0
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

## Multi-Chain Anchoring

APS supports pluggable anchoring to multiple blockchain networks for tamper-evident timestamping of agent artifacts.

### Supported Providers

| Provider | Description | Config |
|----------|-------------|--------|
| **Ethereum** | Any EVM chain (Ethereum, Base, Polygon, Arbitrum, etc.) | RPC URL + contract address + sender address |
| **Arweave** | Permanent storage network | Gateway URL (default: `https://arweave.net`) |
| **NoOp** | Testing/development (no real anchoring) | None |

### Usage (Go)

```go
import "github.com/agent-passport/standard-go/anchor"

// Ethereum (works with any EVM chain)
eth := anchor.NewEthereumProvider(anchor.EthereumConfig{
    RPCURL:          "https://mainnet.base.org",
    ContractAddress: "0x...",
    FromAddress:     "0x...",
    ChainID:         "8453",
})
receipt, _ := eth.Commit(ctx, hash, anchor.AnchorMetadata{ArtifactType: "passport"})

// Arweave
ar := anchor.NewArweaveProvider(anchor.ArweaveConfig{
    GatewayURL: "https://arweave.net",
})
receipt, _ := ar.Commit(ctx, hash, anchor.AnchorMetadata{ArtifactType: "receipt"})
```

All providers implement the same `AnchorProvider` interface (`Commit`, `Verify`, `Info`), making it easy to switch between chains or use multiple chains simultaneously.

---

## Attestation Exchange

APS implements cross-platform attestation exchange based on W3C Verifiable Credentials, enabling agents to present credentials issued by one platform to another.

### Features

- **W3C VC Format** — Attestations follow the Verifiable Credentials data model.
- **Ed25519 Signatures** — All attestations are signed with Ed25519.
- **Trust Registry** — In-memory registry of trusted issuers for verification.
- **Expiry Checking** — Expired attestations are automatically rejected.
- **Tamper Detection** — Any modification invalidates the signature.

### Usage (Go)

```go
import "github.com/agent-passport/standard-go/attestation"

// Create a signed attestation
att, _ := attestation.CreateAttestation(
    "did:key:z6MkIssuer",
    "did:key:z6MkSubject",
    "SkillVerification",
    map[string]interface{}{"skill": "go-backend", "level": "expert"},
    issuerPrivateKey,
)

// Verify
valid, _ := attestation.VerifyAttestation(att, issuerPublicKey)

// Use a trust registry
registry := attestation.NewAttestationRegistry()
registry.RegisterIssuer("did:key:z6MkIssuer", issuerPublicKey)
valid, _ = registry.VerifyFromRegistry(att)
```

See [§13 of the specification](./spec/SPECIFICATION.md) for the full attestation exchange protocol.

---

## Performance Benchmarks

Measured on Intel Core i5-3210M (Go benchmarks via `go test -bench`):

| Operation | Go | Python | TypeScript |
|-----------|----|--------|------------|
| Keccak-256 (44B) | 3.9 µs | < 100 µs | < 50 µs |
| Canonicalize JSON | 54.5 µs | < 200 µs | < 50 µs |
| Ed25519 Sign | 48.9 µs | < 500 µs | ~1.9 ms |
| Ed25519 Verify | 112.9 µs | < 500 µs | ~4.7 ms |
| Passport Create | 87.9 µs | < 1 ms | ~102 µs |
| Passport Sign+Verify | 643.9 µs | < 5 ms | ~5.7 ms |
| Merkle Tree (1000 leaves) | 3.1 ms | < 100 ms | ~60.5 ms |

Run benchmarks: `cd go && go test -bench=. -benchmem .`

---

## Roadmap

- [x] **v0.1** — Core: Passport, Work Receipt, Security Envelope, Anchoring
- [x] **v0.2** — Extended: Agent DNA, Lineage & Heritage, Memory Vault, Collaboration History
- [x] **v0.3** — SDK: Python SDK, TypeScript SDK, CI/CD, Cross-SDK Conformance
- [x] **v1.0** — Stable: Multi-chain anchoring, attestation exchange, security audit, RFC-style spec

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
