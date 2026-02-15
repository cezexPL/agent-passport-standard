# Go SDK — API Reference

## Package `crypto`

```go
import "github.com/cezexPL/agent-passport-standard/go/crypto"
```

### Canonicalization

#### `CanonicalizeJSON(v interface{}) ([]byte, error)`
Produces deterministic JSON with sorted keys (RFC 8785-like).

```go
data, err := crypto.CanonicalizeJSON(map[string]interface{}{"b": 2, "a": 1})
// data = []byte(`{"a":1,"b":2}`)
```

### Hashing

#### `Keccak256(data []byte) string`
Returns `"0x" + hex(keccak256(data))`.

```go
hash := crypto.Keccak256([]byte("hello"))
// hash = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
```

#### `Keccak256Bytes(data []byte) [32]byte`
Returns raw 32-byte digest.

#### `SnapshotHash(payload interface{}) (string, error)`
Canonicalizes `payload` then computes keccak256.

#### `HashExcludingFields(v interface{}, exclude ...string) (string, error)`
Marshals to JSON, removes top-level keys in `exclude`, canonicalizes, returns keccak256.

### Signing

#### `GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error)`
Generates new Ed25519 key pair.

#### `Ed25519Sign(privateKey ed25519.PrivateKey, data []byte) string`
Signs data, returns hex-encoded 128-char signature.

#### `Ed25519Verify(publicKey ed25519.PublicKey, data []byte, signatureHex string) (bool, error)`
Verifies hex-encoded Ed25519 signature.

```go
pub, priv, _ := crypto.GenerateKeyPair()
sig := crypto.Ed25519Sign(priv, []byte("msg"))
ok, _ := crypto.Ed25519Verify(pub, []byte("msg"), sig)
// ok = true
```

### Merkle Tree

#### `NewMerkleTree(leaves []string) *MerkleTree`
Builds binary Merkle tree from hex leaf hashes. Pads to power of 2. Uses sorted-concat keccak256 pairing.

#### `(*MerkleTree) Root() string`
Returns Merkle root hash.

#### `(*MerkleTree) Proof(index int) []string`
Returns sibling hashes for inclusion proof.

#### `VerifyProof(leaf, root string, proof []string, index int) bool`
Verifies a Merkle inclusion proof.

```go
leaves := []string{crypto.Keccak256([]byte("a")), crypto.Keccak256([]byte("b"))}
mt := crypto.NewMerkleTree(leaves)
root := mt.Root()
proof := mt.Proof(0)
ok := crypto.VerifyProof(leaves[0], root, proof, 0) // true
```

### Validation

#### `TimingSafeEqual(a, b string) bool`
Constant-time string comparison.

#### `ValidateDID(s string) error`
Checks `did:key:z6Mk...` format.

#### `ValidateHash(s string) error`
Checks `0x` + 64 hex chars.

#### `ValidateSignature(s string) error`
Checks 128 hex chars (Ed25519).

#### `ValidateTimestamp(s string) error`
Checks RFC 3339 format.

#### `ValidateVersion(v int) error`
Checks positive integer.

#### `ValidateTrustTier(t int) error`
Checks 0–3.

#### `ValidateAttestationCount(c int) error`
Checks non-negative integer.

---

## Package `passport`

```go
import "github.com/cezexPL/agent-passport-standard/go/passport"
```

### Types

- **`AgentPassport`** — Top-level passport document with all fields.
- **`Config`** — Used to create a new passport (`ID`, `PublicKey`, `OwnerDID`, `Skills`, `Soul`, `Policies`, `Lineage`, `EVMAddress`).
- **`Skill`** — `Name`, `Version`, `Description`, `Capabilities`, `Source`, `Hash`.
- **`Soul`** — `Personality`, `WorkStyle`, `Constraints`, `Hash`, `Frozen`.
- **`Policies`** — `PolicySetHash`, `Summary`.
- **`Lineage`** — `Kind`, `Parents`, `Generation`.
- **`Proof`** — Ed25519Signature2020 proof.

### Functions

#### `New(cfg Config) (*AgentPassport, error)`
Creates a new passport, computing snapshot hash automatically.

#### `FromJSON(data []byte) (*AgentPassport, error)`
Parses passport from JSON.

### Methods

#### `(*AgentPassport) Hash() (string, error)`
Computes keccak256 excluding proof field.

#### `(*AgentPassport) Sign(privateKey ed25519.PrivateKey) error`
Signs the passport, setting the `Proof` field.

#### `(*AgentPassport) Verify(publicKey ed25519.PublicKey) (bool, error)`
Verifies the Ed25519 proof.

#### `(*AgentPassport) JSON() ([]byte, error)`
Returns canonical JSON bytes.

### Full Example

```go
pub, priv, _ := crypto.GenerateKeyPair()
cfg := passport.Config{
    ID:       "did:key:z6MkAgent123",
    PublicKey: hex.EncodeToString(pub),
    OwnerDID: "did:key:z6MkOwner456",
    Skills: []passport.Skill{{
        Name: "code-review", Version: "2.0.0",
        Description: "Automated code review",
        Capabilities: []string{"code_review", "test_run"},
        Hash: "0xabc...",
    }},
    Soul: passport.Soul{
        Personality: "Thorough and methodical",
        WorkStyle:   "Sequential, test-driven",
        Constraints: []string{"no-network-access"},
        Hash:        "0xdef...",
    },
    Policies: passport.Policies{PolicySetHash: "0x123...", Summary: []string{"read-only"}},
    Lineage:  passport.Lineage{Kind: "original", Parents: []string{}, Generation: 0},
}

p, _ := passport.New(cfg)
_ = p.Sign(priv)
ok, _ := p.Verify(pub)
fmt.Println("Valid:", ok) // true
```

---

## Package `receipt`

```go
import "github.com/cezexPL/agent-passport-standard/go/receipt"
```

### Types

- **`WorkReceipt`** — Full work receipt document.
- **`Config`** — `ReceiptID`, `JobID`, `AgentDID`, `ClientDID`, `PlatformDID`, `AgentSnapshot`.
- **`ReceiptEvent`** — `Type`, `Timestamp`, `PayloadHash`, `Signature`, `Evidence`, `Result`, `Amount`.
- **`AgentSnapshot`** — `Version`, `Hash`.
- **`VerifyResult`** — `Status`, `Score`, `Stages`.
- **`PayoutAmount`** — `Value`, `Unit`, `Distribution`.
- **`BatchProof`** — `BatchRoot`, `LeafIndex`, `Proof`, `BatchAnchoring`.

### Functions

#### `New(cfg Config) (*WorkReceipt, error)`
#### `FromJSON(data []byte) (*WorkReceipt, error)`

### Methods

#### `(*WorkReceipt) AddEvent(event ReceiptEvent) error`
#### `(*WorkReceipt) Hash() (string, error)`
#### `(*WorkReceipt) Sign(privateKey ed25519.PrivateKey) error`
#### `(*WorkReceipt) Verify(publicKey ed25519.PublicKey) (bool, error)`
#### `(*WorkReceipt) JSON() ([]byte, error)`

### Example: 4-Event Lifecycle

```go
r, _ := receipt.New(receipt.Config{
    ReceiptID: "receipt-001", JobID: "job-001",
    AgentDID: "did:key:z6MkAgent", ClientDID: "did:key:z6MkClient",
    AgentSnapshot: receipt.AgentSnapshot{Version: 1, Hash: "0xabc..."},
})

r.AddEvent(receipt.ReceiptEvent{Type: "claim",  Timestamp: "2026-02-15T10:00:00Z", PayloadHash: "0x...", Signature: "..."})
r.AddEvent(receipt.ReceiptEvent{Type: "submit", Timestamp: "2026-02-15T11:00:00Z", PayloadHash: "0x...", Signature: "..."})
r.AddEvent(receipt.ReceiptEvent{Type: "verify", Timestamp: "2026-02-15T11:30:00Z", PayloadHash: "0x...", Signature: "...",
    Result: &receipt.VerifyResult{Status: "passed", Score: 0.95}})
r.AddEvent(receipt.ReceiptEvent{Type: "payout", Timestamp: "2026-02-15T12:00:00Z", PayloadHash: "0x...", Signature: "...",
    Amount: &receipt.PayoutAmount{Value: 100, Unit: "USDC"}})

_ = r.Sign(priv)
ok, _ := r.Verify(pub)
```

---

## Package `envelope`

```go
import "github.com/cezexPL/agent-passport-standard/go/envelope"
```

### Types

- **`SecurityEnvelope`** — Full envelope document.
- **`Config`** — `AgentDID`, `AgentSnapshotHash`, `Capabilities`, `Sandbox`, `Memory`, `Trust`.
- **`TrustInfo`** — `Tier` (0–3), `AttestationCount`, `HighestAttestation`, `BenchmarkCoverage`, `AnomalyScore`.
- **`Capabilities`** — `Allowed`, `Denied`.
- **`SandboxProfile`** — `Runtime`, `Resources`, `Network`, `Filesystem`.

### Methods

#### `(*SecurityEnvelope) Validate() error`
Validates trust tier rules:
- Tier 1: ≥ 1 attestation
- Tier 2: ≥ 3 attestations, ≥ 0.8 benchmark coverage
- Tier 3: ≥ 10 attestations, ≥ 0.95 benchmark coverage

Also validates runtime ∈ {gvisor, firecracker, wasm, none} and network policy ∈ {deny-all, allow-list, unrestricted}.

---

## Package `anchor`

```go
import "github.com/cezexPL/agent-passport-standard/go/anchor"
```

### Interface

```go
type AnchorProvider interface {
    Commit(ctx context.Context, hash [32]byte, meta AnchorMetadata) (AnchorReceipt, error)
    Verify(ctx context.Context, hash [32]byte) (AnchorVerification, error)
    Info() ProviderInfo
}
```

### Implementations

- **`NoOpProvider`** — Testing stub, always succeeds.
- **`EthereumProvider`** — Anchors to any EVM chain via JSON-RPC (`anchor(bytes32)` / `isAnchored(bytes32)`).
- **`ArweaveProvider`** — Anchors to Arweave via gateway REST/GraphQL.

```go
// Anchor a passport hash
noop := anchor.NewNoOpProvider()
hashBytes := crypto.Keccak256Bytes(passportJSON)
receipt, _ := noop.Commit(ctx, hashBytes, anchor.AnchorMetadata{ArtifactType: "passport"})
```

---

## Package `validate`

```go
import "github.com/cezexPL/agent-passport-standard/go/validate"
```

#### `ValidatePassport(data []byte) error`
#### `ValidateReceipt(data []byte) error`
#### `ValidateEnvelope(data []byte) error`
#### `ValidateDNA(data []byte) error`

Validates JSON bytes against embedded JSON Schema (Draft 2020-12).

---

## Package `compat`

```go
import "github.com/cezexPL/agent-passport-standard/go/compat"
```

#### `ImportAgentSkill(skillDir string) (*passport.Skill, error)`
Reads an Agent Skills folder (SKILL.md) → `passport.Skill`.

#### `ExportAgentSkill(skill *passport.Skill, outputDir string) error`
Writes `passport.Skill` → Agent Skills folder.

#### `LoadAgentsMD(repoPath string) (*AgentsMD, error)`
Parses AGENTS.md → instructions, constraints, tools.
