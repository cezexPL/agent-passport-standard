# APS v1.0 Implementation Guide

**Version:** 1.0.0  
**Date:** 2026-02-15  
**Specification:** `spec/draft-grotowski-aps-v1.md`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Quick Start](#2-quick-start)
3. [Step-by-Step: Create → Sign → Anchor → Verify](#3-step-by-step-create--sign--anchor--verify)
4. [Integrating APS into an Agent Framework](#4-integrating-aps-into-an-agent-framework)
5. [Common Pitfalls](#5-common-pitfalls)
6. [FAQ](#6-faq)
7. [Migration from v0.1/v0.2 to v1.0](#7-migration-from-v01v02-to-v10)

---

## 1. Overview

This guide is for developers implementing the Agent Passport Standard (APS) v1.0 in their agent platforms, frameworks, or tooling. It covers the practical steps to create, sign, anchor, and verify APS artifacts, plus common mistakes and migration advice.

**Prerequisites:**

- Familiarity with Ed25519 signatures, JSON, and hash functions.
- Access to one of the APS SDKs (Go, Python, TypeScript) or willingness to implement from the specification.
- Read `spec/draft-grotowski-aps-v1.md` (the normative specification).

---

## 2. Quick Start

### 2.1. Install an SDK

**Go:**
```bash
go get github.com/agent-passport/aps-go@v1.0.0
```

**Python:**
```bash
pip install agent-passport-standard>=1.0.0
```

**TypeScript:**
```bash
npm install @agent-passport/sdk@^1.0.0
```

### 2.2. Minimal Example (TypeScript)

```typescript
import { createPassport, signPassport, verifyPassport } from '@agent-passport/sdk';

// 1. Generate an Ed25519 key pair
const { publicKey, privateKey } = generateKeyPair();

// 2. Create a passport
const passport = createPassport({
  publicKey,
  owner: { id: 'did:key:z6MkOwner...', name: 'Alice' },
  skills: [{ name: 'code-review', version: '1.0.0' }],
  soul: {
    personality: 'Thorough and methodical code reviewer.',
    constraints: ['Never approve code with known vulnerabilities.'],
  },
  policies: {
    policy_set_hash: '0x...', // keccak256 of your policy document
    summary: ['Review code for security issues.'],
  },
});

// 3. Sign the passport
const signed = signPassport(passport, privateKey);

// 4. Verify
const valid = verifyPassport(signed);
console.log('Valid:', valid); // true
```

---

## 3. Step-by-Step: Create → Sign → Anchor → Verify

### Step 1: Generate Keys

Generate an Ed25519 key pair. The public key will become the agent's DID:

```
did:key:z6Mk<base58btc-encoded-public-key>
```

**Critical:** Store the private key securely (HSM, OS keychain, or encrypted at rest). Never log or transmit it in plaintext.

### Step 2: Define Agent DNA

Construct the three DNA components:

```json
{
  "skills": [
    {
      "name": "typescript-development",
      "version": "2.1.0",
      "proficiency": 0.92,
      "capabilities": ["code.write", "code.review", "test.write"]
    }
  ],
  "soul": {
    "personality": "Detail-oriented developer focused on type safety.",
    "constraints": ["Always use strict TypeScript.", "Never disable linting."],
    "work_style": "Test-driven development with comprehensive coverage."
  },
  "policies": {
    "policy_set_hash": "0xabc123...",
    "summary": ["Write type-safe code.", "Maintain >80% test coverage."],
    "denies": ["code.obfuscation", "dependency.unpinned"]
  }
}
```

### Step 3: Compute Hashes

1. **Canonicalize** the DNA object using RFC 8785 (JCS):
   - Sort keys lexicographically.
   - No whitespace.
   - UTF-8 encoding.

2. **Hash** with Keccak-256 (NOT SHA-3):
   ```
   dna_hash = "0x" + hex(keccak256(canonicalize({skills, soul, policies})))
   ```

3. Verify the hash is exactly 66 characters (`0x` + 64 hex chars).

### Step 4: Build the Passport

Assemble the full passport JSON with all required fields:

- `@context`: `"https://agentpassport.org/v1.0"`
- `spec_version`: `"1.0.0"`
- `type`: `"AgentPassport"`
- `id`: Your `did:key:z6Mk...`
- `keys`: `{ signing: { algorithm: "Ed25519", public_key: "z6Mk..." } }`
- `genesis_owner`: `{ id: "...", name: "...", immutable: true }`
- `current_owner`: Same as genesis_owner initially.
- `snapshot`: `{ version: 1, hash: "<dna_hash>", prev_hash: null, skills: ..., soul: ..., policies: ... }`
- `lineage`: `{ kind: "single", parents: [], generation: 0 }`

### Step 5: Sign

1. Remove the `proof` field (if present) from the passport.
2. Canonicalize the result (RFC 8785).
3. Sign with Ed25519: `signature = Ed25519_Sign(privateKey, canonicalBytes)`.
4. Encode the signature as multibase z-base58btc.
5. Add the `proof` field:

```json
{
  "type": "Ed25519Signature2020",
  "created": "2026-02-15T12:00:00Z",
  "verificationMethod": "did:key:z6Mk...",
  "proofPurpose": "assertionMethod",
  "proofValue": "z<base58btc-signature>"
}
```

### Step 6: Anchor (Optional but Recommended)

1. Compute the passport hash: `keccak256(canonicalize(passport \ {proof}))`.
2. Call your anchoring provider's `Commit(hash, metadata)`.
3. Store the returned `AnchorReceipt` in the passport's `anchoring` field.
4. Re-sign the passport (the anchoring field changed the document).

**Note:** Some implementations anchor after signing by treating the anchor receipt as metadata outside the signed envelope. Choose one approach and be consistent.

### Step 7: Verify

To verify a passport:

1. Extract the `proof` field.
2. Remove `proof` from the document.
3. Canonicalize the remaining document.
4. Extract the public key from the `id` field (`did:key` → Ed25519 public key).
5. Verify: `Ed25519_Verify(publicKey, canonicalBytes, signature)`.
6. Verify `snapshot.hash` matches `keccak256(canonicalize({skills, soul, policies}))`.
7. If `anchoring` is present, verify against the anchoring provider.

---

## 4. Integrating APS into an Agent Framework

### 4.1. Architecture

```
┌─────────────────────────────────────┐
│           Agent Framework           │
│                                     │
│  ┌──────────┐  ┌──────────────────┐ │
│  │  Agent    │  │  APS Module      │ │
│  │  Runtime  │──│                  │ │
│  │          │  │  - Passport Mgr  │ │
│  │          │  │  - Receipt Mgr   │ │
│  │          │  │  - Envelope Mgr  │ │
│  │          │  │  - Crypto        │ │
│  │          │  │  - Anchor Client │ │
│  └──────────┘  └──────────────────┘ │
└─────────────────────────────────────┘
```

### 4.2. Integration Points

1. **Agent creation** → Generate keys, create passport, sign, optionally anchor.
2. **Job claim** → Create Work Receipt with `claim` event.
3. **Job submission** → Add `submit` event with evidence hashes.
4. **Job verification** → Add `verify` event (by platform/verifier).
5. **Agent communication** → Exchange passport snapshots in A2A handshake.
6. **Trust evaluation** → Check attestations, trust tier, collaboration history.

### 4.3. Lifecycle Hooks

```typescript
// Pseudocode for framework integration
agent.on('created', async (agent) => {
  const passport = await aps.createPassport(agent);
  await aps.signPassport(passport, agent.privateKey);
  await aps.anchorPassport(passport);
});

agent.on('job:claimed', async (agent, job) => {
  const receipt = await aps.createReceipt(agent, job, 'claim');
  await aps.signReceipt(receipt, agent.privateKey);
});

agent.on('job:submitted', async (agent, job, evidence) => {
  await aps.addReceiptEvent(receipt, 'submit', evidence);
  await aps.signReceipt(receipt, agent.privateKey);
});

agent.on('skills:updated', async (agent, newSkills) => {
  await aps.mutatePassport(agent, { skills: newSkills, reason: 'Learned new skill from collaboration' });
});
```

### 4.4. Security Envelope Enforcement

The Security Envelope should be enforced by the platform, not the agent itself:

```typescript
// Platform-side enforcement
function executeAgent(agent, envelope) {
  const sandbox = createSandbox(envelope.sandbox);
  sandbox.setResourceLimits(envelope.sandbox.resources);
  sandbox.setNetworkPolicy(envelope.sandbox.network);
  sandbox.setFilesystemPolicy(envelope.sandbox.filesystem);

  // Deny-by-default for capabilities
  const capabilities = new CapabilityChecker(envelope.capabilities);
  sandbox.setCapabilityChecker(capabilities);

  return sandbox.run(agent);
}
```

---

## 5. Common Pitfalls

### 5.1. SHA-3 vs. Keccak-256

**Problem:** Using NIST SHA-3 (FIPS 202) instead of original Keccak-256.

These are different algorithms that produce different output. Ethereum and APS use the pre-NIST Keccak-256.

**How to check:** Hash the empty string `""`:
- Keccak-256: `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
- SHA-3-256:  `0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`

### 5.2. Non-Canonical JSON

**Problem:** Using `JSON.stringify()` or language-default serialization.

`JSON.stringify` does NOT guarantee key ordering across implementations. You MUST use a conforming RFC 8785 (JCS) library.

**Libraries:**
- Go: `github.com/nickvdyck/canonicaljson-go`
- Python: `canonicaljson` package
- TypeScript: `canonicalize` npm package

### 5.3. Mutable genesis_owner

**Problem:** Allowing `genesis_owner` to change on passport update.

The `genesis_owner` field is permanently immutable. Your update logic must preserve it exactly, byte-for-byte after canonicalization.

### 5.4. IV Reuse in AES-256-GCM

**Problem:** Reusing a nonce/IV with the same encryption key.

AES-GCM is catastrophically broken if you reuse an IV. Always generate a fresh 96-bit random IV using a CSPRNG for every encryption operation.

### 5.5. Variable-Time Hash Comparison

**Problem:** Using `==` or string comparison for hash/signature verification.

Use constant-time comparison:
- Go: `crypto/subtle.ConstantTimeCompare`
- Python: `hmac.compare_digest`
- TypeScript: `crypto.timingSafeEqual`

### 5.6. Forgetting snapshot.prev_hash

**Problem:** Not linking snapshots in a hash chain.

Every passport update MUST set `snapshot.prev_hash` to the previous `snapshot.hash`. Version 1 uses `null`.

---

## 6. FAQ

### Q: Can I use a different signature algorithm?

**A:** No. APS v1.0 requires Ed25519 exclusively. This ensures interoperability. Future versions may add algorithm agility.

### Q: Is anchoring required?

**A:** No. Anchoring is OPTIONAL but RECOMMENDED for production use. The `noop` provider exists for development/testing.

### Q: Can an agent have multiple passports?

**A:** An agent has one passport per DID. If an agent needs a new identity, it generates a new key pair and creates a new passport. The two are unrelated unless lineage connects them.

### Q: How do I handle key rotation?

**A:** Create a new passport version with the new key, signed by the old key. Anchor the transition. Verifiers follow the hash chain to validate the rotation.

### Q: What if my platform doesn't support all conformance levels?

**A:** Start with Level 1 (Basic). It requires only JSON schema validation, correct hashes, and valid signatures. Add Level 2 and 3 features incrementally.

### Q: How large can a passport be?

**A:** The spec recommends a 1 MB maximum. In practice, most passports are 5-50 KB. Keep skills, soul, and attestations concise.

### Q: Can I extend the schema with custom fields?

**A:** Yes, via JSON-LD extension. Additional fields not defined in the spec SHOULD be namespaced (e.g., `"x-myplatform-rating": 4.5`). Implementations MUST ignore unknown fields during verification.

---

## 7. Migration from v0.1/v0.2 to v1.0

### 7.1. Summary of Changes

| Aspect | v0.1/v0.2 | v1.0 |
|--------|-----------|------|
| `@context` | `https://agentpassport.org/v0.1` | `https://agentpassport.org/v1.0` |
| `spec_version` | `"0.1.0"` / `"0.2.0"` | `"1.0.0"` |
| Merkle leaf hash | `keccak256(receipt_hash)` | `keccak256(0x00 \|\| receipt_hash)` |
| Merkle node hash | `keccak256(left \|\| right)` | `keccak256(0x01 \|\| min(l,r) \|\| max(l,r))` |
| Attestation structure | Informal | Formalized (Section 11) |
| Media types | None | 3 registered types |

### 7.2. Migration Steps

#### Step 1: Update Context and Version

```diff
- "@context": "https://agentpassport.org/v0.1",
- "spec_version": "0.1.0",
+ "@context": "https://agentpassport.org/v1.0",
+ "spec_version": "1.0.0",
```

#### Step 2: Create a New Snapshot Version

Migration requires a snapshot version bump:

1. Increment `snapshot.version`.
2. Set `snapshot.prev_hash` to the current `snapshot.hash`.
3. Recompute `snapshot.hash` (the DNA content may be unchanged, but the version context changed).
4. Set `mutation_reason` to `"Migration from v0.x to v1.0"`.

#### Step 3: Update Merkle Tree Implementation

If you use batch proofs, update your Merkle tree to use domain separation:

```typescript
// Before (v0.1/v0.2)
const leafHash = keccak256(receiptHash);
const nodeHash = keccak256(concat(left, right)); // unordered

// After (v1.0)
const leafHash = keccak256(concat(0x00, receiptHash));
const nodeHash = keccak256(concat(0x01, min(left, right), max(left, right)));
```

#### Step 4: Formalize Attestations

If you have existing attestations, restructure them to match Section 11.2:

```json
{
  "type": "capability",
  "issuer": "did:key:z6Mk...",
  "subject": "did:key:z6Mk...",
  "issued_at": "2026-02-15T12:00:00Z",
  "claims": { "verified_skills": ["code-review"] },
  "proof": { ... }
}
```

#### Step 5: Re-sign and Re-anchor

After migration:

1. Re-sign the passport with the agent's key.
2. Re-anchor if using anchoring.
3. Validate against v1.0 test vectors.

### 7.3. Backward Compatibility

- v0.1/v0.2 passports remain structurally valid JSON but do not conform to v1.0.
- Implementations MAY accept v0.1/v0.2 passports in a compatibility mode but MUST NOT claim v1.0 conformance for them.
- The snapshot hash chain provides continuity: a v1.0 snapshot can reference a v0.2 `prev_hash`, establishing the migration link.

---

## License

Copyright © 2026 Cezary Grotowski. Licensed under [Apache License 2.0](../LICENSE).
