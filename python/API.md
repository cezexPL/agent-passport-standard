# Python SDK — API Reference

```python
import aps
# or import individual modules:
from aps import crypto, passport, receipt, envelope, anchor, compat
```

---

## Module `aps.crypto`

### Canonicalization

#### `canonicalize_json(obj: Any) -> bytes`
Returns deterministic UTF-8 JSON bytes with sorted keys (RFC 8785-like).

```python
data = canonicalize_json({"b": 2, "a": 1})
# b'{"a":1,"b":2}'
```

### Hashing

#### `keccak256(data: bytes) -> str`
Returns `"0x" + hex(keccak256(data))`.

#### `keccak256_bytes(data: bytes) -> bytes`
Returns raw 32-byte digest.

#### `snapshot_hash(payload: Any) -> str`
Canonicalize then keccak256.

#### `hash_excluding_fields(obj: Any, *exclude: str) -> str`
Marshal to JSON, remove top-level keys, canonicalize, keccak256.

### Signing

#### `generate_key_pair() -> tuple[Ed25519PublicKey, Ed25519PrivateKey]`
Generate new Ed25519 key pair.

#### `ed25519_sign(private_key: Ed25519PrivateKey, data: bytes) -> str`
Sign data, return 128-char hex signature.

#### `ed25519_verify(public_key: Ed25519PublicKey, data: bytes, signature_hex: str) -> bool`
Verify hex-encoded signature. Returns `True`/`False`.

```python
pub, priv = generate_key_pair()
sig = ed25519_sign(priv, b"hello")
assert ed25519_verify(pub, b"hello", sig) == True
```

### Merkle Tree

#### `class MerkleTree(leaves: list[str])`
Binary Merkle tree using keccak256 with sorted-concat pairing.

- **`root() -> str`** — Merkle root hash.
- **`proof(index: int) -> list[str]`** — Sibling hashes for inclusion proof.

#### `verify_proof(leaf: str, root: str, proof: list[str], index: int) -> bool`

```python
leaves = [keccak256(b"a"), keccak256(b"b")]
mt = MerkleTree(leaves)
assert verify_proof(leaves[0], mt.root(), mt.proof(0), 0)
```

### Validation

| Function | Validates |
|----------|-----------|
| `validate_did(s)` | `did:key:z6Mk...` format |
| `validate_hash(s)` | `0x` + 64 hex chars |
| `validate_signature(s)` | 128 hex chars |
| `validate_timestamp(s)` | ISO 8601 |
| `validate_version(v)` | Positive integer |
| `validate_trust_tier(t)` | 0–3 |
| `validate_attestation_count(c)` | Non-negative integer |

#### `timing_safe_equal(a: str, b: str) -> bool`
Constant-time comparison.

---

## Module `aps.passport`

### Classes

#### `PassportConfig`
Dataclass: `id`, `public_key`, `owner_did`, `skills`, `soul`, `policies`, `lineage`, `evm_address`.

#### `Skill`
Dataclass: `name`, `version`, `description`, `capabilities`, `hash`, `source`.

#### `Soul`
Dataclass: `personality`, `work_style`, `constraints`, `hash`, `frozen`.

#### `Policies`
Dataclass: `policy_set_hash`, `summary`.

#### `Lineage`
Dataclass: `kind`, `parents`, `generation`.

#### `class AgentPassport`

| Method | Signature |
|--------|-----------|
| `AgentPassport.new(cfg)` | `@staticmethod -> AgentPassport` |
| `hash()` | `-> str` |
| `sign(private_key)` | `-> None` |
| `verify(public_key)` | `-> bool` |
| `to_json()` | `-> bytes` |
| `AgentPassport.from_json(data)` | `@staticmethod -> AgentPassport` |
| `to_dict()` | `-> dict` |

### Full Example

```python
from aps import AgentPassport, PassportConfig, Skill, Soul, Policies, Lineage
from aps.crypto import generate_key_pair
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

pub, priv = generate_key_pair()
pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

cfg = PassportConfig(
    id="did:key:z6MkAgent123",
    public_key=pub_hex,
    owner_did="did:key:z6MkOwner456",
    skills=[Skill("code-review", "2.0.0", "Code review", ["code_review"], "0xabc...")],
    soul=Soul("Thorough", "Sequential", ["no-network"], "0xdef..."),
    policies=Policies("0x123...", ["read-only"]),
    lineage=Lineage("original", [], 0),
)

p = AgentPassport.new(cfg)
p.sign(priv)
assert p.verify(pub) == True
```

---

## Module `aps.receipt`

#### `ReceiptConfig`
Dataclass: `receipt_id`, `job_id`, `agent_did`, `client_did`, `agent_snapshot`, `platform_did`.

#### `class WorkReceipt`

| Method | Signature |
|--------|-----------|
| `WorkReceipt.new(cfg)` | `@staticmethod -> WorkReceipt` |
| `add_event(event: dict)` | `-> None` |
| `hash()` | `-> str` |
| `sign(private_key)` | `-> None` |
| `verify(public_key)` | `-> bool` |
| `to_json()` | `-> bytes` |
| `WorkReceipt.from_json(data)` | `@staticmethod -> WorkReceipt` |

### Example: 4-Event Lifecycle

```python
from aps import WorkReceipt, ReceiptConfig

r = WorkReceipt.new(ReceiptConfig(
    receipt_id="receipt-001", job_id="job-001",
    agent_did="did:key:z6MkAgent", client_did="did:key:z6MkClient",
    agent_snapshot={"version": 1, "hash": "0xabc..."},
))

r.add_event({"type": "claim",  "timestamp": "2026-02-15T10:00:00Z", "payload_hash": "0x...", "signature": "..."})
r.add_event({"type": "submit", "timestamp": "2026-02-15T11:00:00Z", "payload_hash": "0x...", "signature": "..."})
r.add_event({"type": "verify", "timestamp": "2026-02-15T11:30:00Z", "payload_hash": "0x...", "signature": "...",
             "result": {"status": "passed", "score": 0.95}})
r.add_event({"type": "payout", "timestamp": "2026-02-15T12:00:00Z", "payload_hash": "0x...", "signature": "...",
             "amount": {"value": 100, "unit": "USDC"}})

r.sign(priv)
assert r.verify(pub) == True
```

---

## Module `aps.envelope`

#### `EnvelopeConfig`
Dataclass: `agent_did`, `agent_snapshot_hash`, `capabilities`, `sandbox`, `memory`, `trust`.

#### `class SecurityEnvelope`

| Method | Signature |
|--------|-----------|
| `SecurityEnvelope.new(cfg)` | `@staticmethod -> SecurityEnvelope` |
| `hash()` | `-> str` |
| `validate()` | `-> None` (raises `ValueError`) |
| `sign(private_key)` | `-> None` |
| `verify(public_key)` | `-> bool` |
| `to_json()` | `-> bytes` |
| `SecurityEnvelope.from_json(data)` | `@staticmethod -> SecurityEnvelope` |

Trust tier validation:
- Tier 1: ≥ 1 attestation
- Tier 2: ≥ 3 attestations, ≥ 0.8 benchmark coverage
- Tier 3: ≥ 10 attestations, ≥ 0.95 benchmark coverage

---

## Module `aps.anchor`

#### `class AnchorProvider(ABC)`
Abstract: `commit(hash_bytes, meta) -> AnchorReceipt`, `verify(hash_bytes) -> AnchorVerification`, `info() -> ProviderInfo`.

#### `class NoopAnchor(AnchorProvider)`
Testing stub.

```python
from aps import NoopAnchor, AnchorMetadata
from aps.crypto import keccak256_bytes

a = NoopAnchor()
receipt = a.commit(keccak256_bytes(b"data"), AnchorMetadata("passport"))
assert receipt.provider == "noop"
```

---

## Module `aps.compat`

#### `import_agent_skill(skill_dir: str) -> Skill`
Reads Agent Skills folder → `Skill`.

#### `export_agent_skill(skill: Skill, output_dir: str) -> None`
Writes `Skill` → Agent Skills folder.

#### `load_agents_md(repo_path: str) -> AgentsMD`
Parses AGENTS.md → `AgentsMD` with `raw`, `instructions`, `constraints`, `tools`.
