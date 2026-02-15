# TypeScript SDK — API Reference

```typescript
import {
  canonicalizeJson, keccak256, keccak256Bytes, snapshotHash, hashExcludingFields,
  ed25519Sign, ed25519Verify, generateKeyPair, MerkleTree, hexToBytes, timingSafeEqual,
  validateDid, validateHash, validateSignature, validateTimestamp, validateVersion,
  validateTrustTier, validateAttestationCount,
  AgentPassport, WorkReceipt, SecurityEnvelope, NoopAnchor,
  importAgentSkill, exportAgentSkill, loadAgentsMd,
} from 'aps-sdk';
```

---

## Crypto

### Canonicalization

#### `canonicalizeJson(value: unknown): string`
Deterministic JSON string with sorted keys (RFC 8785-like).

### Hashing

#### `keccak256(data: Uint8Array): string`
Returns `"0x" + hex(keccak256(data))`.

#### `keccak256Bytes(data: Uint8Array): Uint8Array`
Returns raw 32-byte hash.

#### `snapshotHash(payload: unknown): string`
Canonicalize then keccak256.

#### `hashExcludingFields(v: unknown, ...exclude: string[]): string`
Remove top-level keys, canonicalize, keccak256.

### Signing

#### `generateKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array }`

#### `ed25519Sign(privateKey: Uint8Array, data: Uint8Array): Promise<string>`
Returns hex signature.

#### `ed25519Verify(publicKey: Uint8Array, data: Uint8Array, signatureHex: string): Promise<boolean>`

```typescript
const { publicKey, privateKey } = generateKeyPair();
const sig = await ed25519Sign(privateKey, new TextEncoder().encode('hello'));
const ok = await ed25519Verify(publicKey, new TextEncoder().encode('hello'), sig);
// ok === true
```

### Merkle Tree

#### `class MerkleTree`
```typescript
constructor(leaves: string[])
root(): string
proof(index: number): string[]
static verifyProof(leaf: string, root: string, proof: string[], index: number): boolean
```

### Utilities

#### `hexToBytes(hex: string): Uint8Array`
#### `timingSafeEqual(a: string, b: string): boolean`

### Validation

All throw `Error` on invalid input:

| Function | Validates |
|----------|-----------|
| `validateDid(s)` | `did:key:z6Mk...` |
| `validateHash(s)` | `0x` + 64 hex |
| `validateSignature(s)` | 128 hex chars |
| `validateTimestamp(s)` | ISO 8601 |
| `validateVersion(v)` | Positive integer |
| `validateTrustTier(t)` | 0–3 |
| `validateAttestationCount(c)` | Non-negative |

---

## AgentPassport

```typescript
class AgentPassport {
  data: AgentPassportData;
  static async create(cfg: PassportConfig): Promise<AgentPassport>;
  static fromJson(json: string): AgentPassport;
  toJson(): string;
  hash(): string;
  async sign(privateKey: Uint8Array): Promise<void>;
  async verify(publicKey: Uint8Array): Promise<boolean>;
  addSkill(skill: Skill): void;
  newSnapshot(): void;
}
```

### `PassportConfig`
```typescript
interface PassportConfig {
  id: string;
  publicKey: string;
  ownerDID: string;
  skills: Skill[];
  soul: Soul;
  policies: Policies;
  lineage: Lineage;
  evmAddress?: string;
}
```

### Full Example

```typescript
import { AgentPassport, generateKeyPair } from 'aps-sdk';
import { bytesToHex } from '@noble/hashes/utils';

const { publicKey, privateKey } = generateKeyPair();
const passport = await AgentPassport.create({
  id: 'did:key:z6MkAgent123',
  publicKey: bytesToHex(publicKey),
  ownerDID: 'did:key:z6MkOwner456',
  skills: [{ name: 'code-review', version: '2.0.0', description: 'Review', capabilities: ['code_review'], hash: '0xabc...' }],
  soul: { personality: 'Thorough', work_style: 'Sequential', constraints: ['no-network'], hash: '0xdef...', frozen: false },
  policies: { policy_set_hash: '0x123...', summary: ['read-only'] },
  lineage: { kind: 'original', parents: [], generation: 0 },
});

await passport.sign(privateKey);
const valid = await passport.verify(publicKey); // true
```

---

## WorkReceipt

```typescript
class WorkReceipt {
  data: WorkReceiptData;
  static create(cfg: ReceiptConfig): WorkReceipt;
  static fromJson(json: string): WorkReceipt;
  toJson(): string;
  addEvent(event: ReceiptEvent): void;
  hash(): string;
  async sign(privateKey: Uint8Array): Promise<void>;
  async verify(publicKey: Uint8Array): Promise<boolean>;
}
```

### `ReceiptConfig`
```typescript
interface ReceiptConfig {
  receiptId: string;
  jobId: string;
  agentDID: string;
  clientDID: string;
  platformDID?: string;
  agentSnapshot: { version: number; hash: string };
}
```

### Example: 4-Event Lifecycle

```typescript
const r = WorkReceipt.create({
  receiptId: 'receipt-001', jobId: 'job-001',
  agentDID: 'did:key:z6MkAgent', clientDID: 'did:key:z6MkClient',
  agentSnapshot: { version: 1, hash: '0xabc...' },
});

r.addEvent({ type: 'claim',  timestamp: '2026-02-15T10:00:00Z', payload_hash: '0x...', signature: '...' });
r.addEvent({ type: 'submit', timestamp: '2026-02-15T11:00:00Z', payload_hash: '0x...', signature: '...' });
r.addEvent({ type: 'verify', timestamp: '2026-02-15T11:30:00Z', payload_hash: '0x...', signature: '...',
             result: { status: 'passed', score: 0.95 } });
r.addEvent({ type: 'payout', timestamp: '2026-02-15T12:00:00Z', payload_hash: '0x...', signature: '...',
             amount: { value: 100, unit: 'USDC' } });

await r.sign(privateKey);
const valid = await r.verify(publicKey); // true
```

---

## SecurityEnvelope

```typescript
class SecurityEnvelope {
  data: SecurityEnvelopeData;
  static create(cfg: EnvelopeConfig): SecurityEnvelope;
  static fromJson(json: string): SecurityEnvelope;
  toJson(): string;
  hash(): string;
  validate(): void;
  async sign(privateKey: Uint8Array): Promise<void>;
}
```

### `EnvelopeConfig`
```typescript
interface EnvelopeConfig {
  agentDID: string;
  agentSnapshotHash: string;
  capabilities: { allowed: string[]; denied: string[] };
  sandbox: SandboxProfile;
  memory: MemoryBoundary;
  trust: TrustInfo;
}
```

Trust tier validation:
- **Tier 0**: No requirements
- **Tier 1**: ≥ 1 attestation
- **Tier 2**: ≥ 3 attestations, ≥ 0.8 benchmark coverage
- **Tier 3**: ≥ 10 attestations, ≥ 0.95 benchmark coverage

---

## Anchoring

```typescript
interface AnchorProvider {
  commit(hash: Uint8Array, meta: AnchorMetadata): Promise<AnchorReceipt>;
  verify(hash: Uint8Array): Promise<AnchorVerification>;
  info(): ProviderInfo;
}

class NoopAnchor implements AnchorProvider { ... }
```

```typescript
const anchor = new NoopAnchor();
const receipt = await anchor.commit(keccak256Bytes(data), { artifact_type: 'passport', description: '' });
```

---

## Compat

#### `importAgentSkill(skillDir: string): Skill`
#### `exportAgentSkill(skill: Skill, outputDir: string): void`
#### `loadAgentsMd(repoPath: string): AgentsMD`

---

## Types

All types exported from `aps-sdk`:

`AgentPassportData`, `PassportConfig`, `Skill`, `Soul`, `Policies`, `Lineage`, `Snapshot`, `Keys`, `SigningKey`, `EVMKey`, `GenesisOwner`, `CurrentOwner`, `Proof`, `BenchmarkResult`, `Attestation`, `Anchoring`, `WorkReceiptData`, `ReceiptConfig`, `ReceiptEvent`, `AgentSnapshotRef`, `VerifyResult`, `PayoutAmount`, `BatchProof`, `BatchAnchoring`, `SecurityEnvelopeData`, `EnvelopeConfig`, `Capabilities`, `SandboxProfile`, `Resources`, `NetworkPolicy`, `Filesystem`, `MemoryBoundary`, `MemoryRules`, `Vault`, `TrustInfo`, `AnchorReceipt`, `AnchorVerification`, `ProviderInfo`, `AnchorMetadata`, `AgentsMD`
