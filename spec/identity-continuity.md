# §19 Identity Continuity & Key Rotation

> **APS v1.1 Extension** — Draft, February 2026
>
> This section extends the Agent Passport Standard (APS) v1.0 to address
> agent identity persistence across key rotations, model upgrades, and
> key compromise scenarios.

## Status

This document is a normative extension to APS v1.0 (draft-grotowski-aps-01).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

---

## 19.1 Motivation

Agent identity loss during upgrades is the most-reported pain point in
production APS deployments. When an agent rotates keys — whether due to
routine hygiene, model upgrade, or compromise — downstream verifiers lose
the ability to link the new identity to the agent's prior reputation,
work receipts, and attestations.

This section defines a deterministic protocol for key rotation that
preserves identity continuity, carries reputation forward, and handles
compromise recovery.

---

## 19.2 Key Rotation Protocol

### 19.2.1 Overview

An agent MAY rotate its signing key at any time. The rotation MUST be
authorized by the OLD key (or via the Recovery Flow in §19.5 if the old
key is compromised).

### 19.2.2 Procedure

1. Agent generates a new Ed25519 keypair per RFC 8032.
2. Agent derives the new DID from the new public key (e.g., `did:key:z6Mk...`).
3. Agent constructs a Rotation Declaration (§19.3) and signs it with the OLD private key.
4. The new Agent Passport MUST include a `previous_did` field linking to the old DID.
5. The Rotation Declaration MUST be anchored on-chain per §4 (Anchoring).
6. The new passport `snapshot.version` MUST be incremented.
7. The new passport `snapshot.prev_hash` MUST chain from the last snapshot hash.

### 19.2.3 New Passport Fields

The following fields are added to the Agent Passport (§1.2):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `previous_did` | string | CONDITIONAL | DID of the agent's prior identity. MUST be present if this passport results from a key rotation. `null` for genesis passports. |
| `rotation_proof` | string | CONDITIONAL | Content-addressed hash of the Rotation Declaration. MUST be present when `previous_did` is set. |
| `active_keys` | array | OPTIONAL | List of active key objects (§19.8). When absent, only the primary key in `keys` is active. |

---

## 19.3 Rotation Declaration

### 19.3.1 Schema

A Rotation Declaration is a signed JSON document with the following structure:

```json
{
  "type": "KeyRotation",
  "spec_version": "1.1.0",
  "old_did": "did:key:z6MkOLD...",
  "new_did": "did:key:z6MkNEW...",
  "reason": "scheduled | upgrade | compromise | owner-transfer",
  "rotated_at": "2026-02-16T01:13:00Z",
  "chain_position": 3,
  "metadata": {
    "agent_name": "example-agent",
    "upgrade_details": "model upgrade from gpt-4 to gpt-5"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-16T01:13:00Z",
    "verification_method": "did:key:z6MkOLD...#key-1",
    "proof_purpose": "authentication",
    "proof_value": "z..."
  }
}
```

### 19.3.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | MUST | Literal `"KeyRotation"`. |
| `spec_version` | string | MUST | `"1.1.0"` for this version. |
| `old_did` | string | MUST | The DID being rotated FROM. |
| `new_did` | string | MUST | The DID being rotated TO. |
| `reason` | enum | MUST | One of: `scheduled`, `upgrade`, `compromise`, `owner-transfer`. |
| `rotated_at` | string | MUST | ISO 8601 timestamp of rotation. |
| `chain_position` | integer | MUST | 1-indexed position in the identity continuity chain. Genesis = 1, first rotation = 2. |
| `metadata` | object | OPTIONAL | Free-form metadata about the rotation context. |
| `proof` | object | MUST | Ed25519Signature2020 proof signed by the OLD key. |

### 19.3.3 Signing

The `proof` field MUST be computed over the canonical JSON (RFC 8785) of the
declaration **excluding** the `proof` field:

```
message = canonicalize(declaration - proof)
signature = Ed25519.sign(old_private_key, message)
```

### 19.3.4 Anchoring

The Rotation Declaration MUST be anchored on-chain per APS §4. The anchoring
receipt MUST be stored in the new passport's `anchoring` field. Implementations
SHOULD anchor within 1 hour of rotation.

### 19.3.5 Exception: Compromise

When `reason` is `"compromise"`, the old key is assumed unavailable.
The declaration MUST instead follow the Recovery Flow (§19.5).

---

## 19.4 Identity Continuity Chain

### 19.4.1 Structure

The Identity Continuity Chain is a singly-linked list of DIDs, ordered from
current (head) to genesis (tail). Each node links to its predecessor via
`previous_did` and is authenticated by its corresponding Rotation Declaration.

```
[DID_current] --previous_did--> [DID_n-1] --...--> [DID_genesis]
                                                     previous_did: null
```

### 19.4.2 Verification

To verify an Identity Continuity Chain:

1. Start from the current passport. Extract `previous_did` and `rotation_proof`.
2. Retrieve the Rotation Declaration by its content-addressed hash (`rotation_proof`).
3. Verify the Rotation Declaration's `proof` against the `old_did`'s public key.
4. Confirm `old_did` matches `previous_did` and `new_did` matches the current DID.
5. Confirm `chain_position` is monotonically increasing from genesis.
6. Repeat from step 1 using the previous passport until `previous_did` is `null`.
7. The final passport (where `previous_did` is `null`) is the genesis passport.

If ANY step fails, the chain MUST be considered broken and the identity
MUST NOT be treated as continuous.

### 19.4.3 Reputation Continuity

When a valid Identity Continuity Chain exists:

- All work receipts (§2) issued under any DID in the chain MUST be considered
  as belonging to the same logical agent.
- Reputation scores MUST carry forward across rotations.
- Attestations (§1.2) issued to any DID in the chain MUST be resolvable
  against the current DID.
- Verifiers SHOULD resolve the full chain before computing reputation.

### 19.4.4 Chain Depth Limit

Implementations MUST support chains of at least 256 rotations.
Implementations MAY reject chains deeper than 1024 rotations.

---

## 19.5 Recovery Flow (Key Compromise)

### 19.5.1 Overview

When an agent's private key is compromised, the standard rotation protocol
(§19.2) cannot be used because the old key is no longer trustworthy. The
Recovery Flow provides an alternative path that relies on platform attestation
and owner verification.

### 19.5.2 Procedure

1. **Owner Declaration**: The `current_owner` (§1.2) signs a Recovery Request
   containing the compromised DID and the proposed new DID. The owner's
   signature method is determined by the owner's DID method.

2. **Platform Attestation**: The hosting platform (identified by its own DID)
   MUST issue an attestation confirming:
   - The agent with the compromised DID was running on its infrastructure.
   - The owner requesting recovery matches the `current_owner` on record.
   - The new keypair was generated in a secure environment.

3. **Recovery Declaration**: A special Rotation Declaration is constructed:

```json
{
  "type": "KeyRotation",
  "spec_version": "1.1.0",
  "old_did": "did:key:z6MkCOMPROMISED...",
  "new_did": "did:key:z6MkNEW...",
  "reason": "compromise",
  "rotated_at": "2026-02-16T01:13:00Z",
  "chain_position": 4,
  "recovery": {
    "owner_proof": { "...owner signature..." },
    "platform_attestation": { "...platform attestation..." },
    "cooldown_until": "2026-02-23T01:13:00Z"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-16T01:13:00Z",
    "verification_method": "did:key:z6MkNEW...#key-1",
    "proof_purpose": "authentication",
    "proof_value": "z..."
  }
}
```

4. **Cooldown Period**: The recovery MUST include a cooldown period of at least
   **7 days** (`cooldown_until`). During this period:
   - The new DID is in `pending-recovery` state.
   - Work receipts issued by the new DID SHOULD carry a `recovery_pending` flag.
   - The compromised DID's key MUST be immediately revoked for new signatures.
   - Any party MAY challenge the recovery by presenting counter-evidence.

5. **Activation**: After the cooldown period expires without challenge, the
   new DID becomes fully active and the Identity Continuity Chain is extended.

### 19.5.3 Recovery Declaration Signing

Since the old key is compromised, the Recovery Declaration `proof` MUST be
signed by the NEW key. Authenticity is established through the combination
of owner proof + platform attestation rather than old-key continuity.

### 19.5.4 Revocation of Compromised Key

Upon initiating recovery, the compromised DID MUST be added to the
Revocation List (§13.5.1) with reason `"key-compromise"`. Signatures made
by the compromised key after the `rotated_at` timestamp MUST be considered
invalid.

---

## 19.6 Upgrade Persistence

### 19.6.1 Overview

When an agent undergoes a model or runtime upgrade (e.g., switching LLM
providers, updating to a new model version), its identity MUST persist.
The upgrade is recorded as a snapshot version increment, not an identity change.

### 19.6.2 Immutability Rules for Upgrades

The following fields MUST NOT change during an upgrade:

| Field | Rationale |
|-------|-----------|
| `id` (DID) | Identity anchor. Change requires key rotation, not upgrade. |
| `genesis_owner` | Immutable per §1.3. |
| `current_owner` | Ownership transfer is a separate protocol. |
| `previous_did` | Historical chain. |
| `lineage` | Derivation history is immutable. |

The following fields MAY change during an upgrade:

| Field | Constraint |
|-------|------------|
| `snapshot.skills` | MAY change unless `snapshot.skills.frozen` is `true`. |
| `snapshot.soul` | MAY change unless `snapshot.soul.frozen` is `true`. |
| `snapshot.policies` | MAY change. New policies MUST be valid per §3. |
| `snapshot.version` | MUST increment. |
| `snapshot.hash` | MUST be recomputed. |
| `snapshot.prev_hash` | MUST reference previous snapshot hash. |
| `benchmarks` | SHOULD be re-run after upgrade. |
| `attestations` | Prior attestations remain valid. New ones MAY be added. |

### 19.6.3 Upgrade Without Key Rotation

If the agent's key material does not change, no Rotation Declaration is
needed. The agent simply publishes a new passport version with an incremented
`snapshot.version`, re-signs with the same key, and optionally re-anchors.

### 19.6.4 Upgrade With Key Rotation

If the upgrade also involves new key material (e.g., the agent migrates to
a new secure enclave), the agent MUST follow the Key Rotation Protocol (§19.2)
with `reason: "upgrade"` in the Rotation Declaration.

---

## 19.7 Deprecation Timeline

### 19.7.1 Post-Rotation Key Validity

After a successful key rotation, the OLD key enters a deprecation lifecycle:

| Phase | Duration | Old Key Status |
|-------|----------|----------------|
| **Active** | 0–90 days after rotation | Valid for VERIFICATION of past signatures. MUST NOT be used for new signatures. |
| **Deprecated** | 90–365 days after rotation | Marked `deprecated`. Verifiers SHOULD warn but MAY still verify. |
| **Expired** | >365 days after rotation | Verifiers MAY reject. Signatures remain valid if anchored on-chain. |

### 19.7.2 Implementation

- Verifiers MUST check the `rotated_at` timestamp of the Rotation Declaration
  to determine the old key's phase.
- The old key MUST NOT be used to sign new documents after rotation.
- On-chain anchored signatures remain permanently verifiable regardless of
  deprecation phase, as the chain provides an immutable timestamp proof.

### 19.7.3 Compromise Override

If the rotation reason is `"compromise"`, the old key is immediately invalid
for all purposes. The deprecation timeline does NOT apply. The key MUST be
added to the Revocation List (§13.5.1) immediately.

---

## 19.8 Multi-Key Support

### 19.8.1 Overview

An agent MAY maintain multiple active keys simultaneously. This enables
backup keys, cross-platform operation, and graceful rotation without downtime.

### 19.8.2 Active Keys Array

When multi-key is used, the passport MUST include an `active_keys` array:

```json
{
  "active_keys": [
    {
      "id": "did:key:z6MkPRIMARY...#key-1",
      "type": "Ed25519VerificationKey2020",
      "role": "primary",
      "added_at": "2026-01-01T00:00:00Z",
      "expires_at": null
    },
    {
      "id": "did:key:z6MkBACKUP...#key-2",
      "type": "Ed25519VerificationKey2020",
      "role": "backup",
      "added_at": "2026-01-01T00:00:00Z",
      "expires_at": "2027-01-01T00:00:00Z"
    }
  ]
}
```

### 19.8.3 Key Roles

| Role | Count | Purpose |
|------|-------|---------|
| `primary` | Exactly 1 | Default signing key. Used for passports, work receipts, and all normal operations. |
| `backup` | 0 or more | Used for recovery if primary is lost. MUST NOT be used for normal operations unless primary is revoked. |
| `delegation` | 0 or more | Scoped key for specific platforms or tasks. MAY sign work receipts but MUST NOT sign passports or rotation declarations. |

### 19.8.4 Priority Rules

1. The `primary` key MUST be used for signing passports and rotation declarations.
2. A `backup` key MAY sign a Rotation Declaration ONLY when the primary key
   is compromised. This follows the standard rotation protocol (§19.2), not
   the Recovery Flow, because the backup key was pre-authorized.
3. A `delegation` key MUST NOT sign passports, rotation declarations, or
   recovery requests.
4. If a passport is signed by a non-`primary` key, verifiers MUST reject it
   unless the signer is a `backup` key AND a valid Rotation Declaration
   exists revoking the former primary.

### 19.8.5 Adding and Removing Keys

- Adding a new key to `active_keys` requires a new passport version signed
  by the `primary` key.
- Removing a key requires a new passport version signed by the `primary` key.
  The removed key SHOULD be added to the Revocation List.
- The `primary` key MUST NOT be removed without a simultaneous rotation
  promoting another key to `primary`.

---

## 19.9 Identity Attestations

### 19.9.1 Overview

An agent MAY present cryptographic proof of real-world identity without
revealing the underlying identity data. Identity attestations enable
platforms to distinguish unique humans (or organizations) behind agents,
strengthening anti-sybil measures (§21) while preserving privacy.

### 19.9.2 Attestation Object

The Agent Passport MAY include an `identity_attestations` array. Each
element MUST conform to the following structure:

```json
{
  "identity_attestations": [
    {
      "provider": "self.xyz",
      "method": "zk-passport-nfc",
      "level": "hardware",
      "proof_hash": "0x...",
      "verified_at": "2026-02-16T00:00:00Z",
      "expires_at": "2027-02-16T00:00:00Z"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | MUST | Identifier of the attestation provider (e.g., a domain name). Provider names are informational; verification relies on `proof_hash`. |
| `method` | string | MUST | The verification method used (e.g., `"zk-passport-nfc"`, `"social-graph"`, `"iris-scan"`). |
| `level` | enum | MUST | One of the attestation levels defined in §19.9.3. |
| `proof_hash` | string | MUST | Content-addressed hash of the zero-knowledge proof or verification artifact. Platforms MUST NOT store raw identity data — only this hash. |
| `verified_at` | string | MUST | ISO 8601 timestamp of when the attestation was verified. |
| `expires_at` | string | MUST | ISO 8601 timestamp of when the attestation expires. Expired attestations MUST NOT contribute to reputation weighting. |

### 19.9.3 Attestation Levels

Attestation levels are ordered from weakest to strongest assurance of
unique personhood. Higher levels provide greater confidence that the
agent is backed by a distinct real-world entity.

| Level | Numeric Weight | Description | Examples (informational) |
|-------|---------------|-------------|--------------------------|
| `social` | 1 | Social graph proof — verification through a web-of-trust or social vouching mechanism. | Gitcoin Passport, BrightID |
| `email` | 2 | Verified email domain — proof of control over an email address at a verified domain. | Corporate email verification |
| `document` | 3 | KYC document review — identity document reviewed by a licensed verification provider. | Government ID review |
| `biometric` | 4 | Biometric scan — iris, face, or voice biometric uniqueness proof. | Worldcoin iris scan |
| `hardware` | 5 | Physical document NFC + ZK proof — cryptographic proof derived from NFC-readable identity documents (e.g., ePassport chip) combined with zero-knowledge proofs. | Self.xyz passport attestation |

### 19.9.4 Stacking

Multiple attestations from different levels MUST stack additively for
reputation weighting purposes (§21). An agent holding both a `hardware`
and a `social` attestation MUST receive a higher reputation weight than
an agent holding only a `hardware` attestation.

The effective attestation multiplier `M` is computed as:

```
M = base_multiplier(max_level) + 0.05 × (count_of_additional_levels)
```

Where `base_multiplier` is defined in §21.4.2.

### 19.9.5 Expiry and Renewal

- Attestations MUST include an expiration timestamp (`expires_at`).
- Expired attestations MUST be excluded from reputation weight computation.
- Agents SHOULD renew attestations before expiry to avoid reputation weight
  reduction.
- Platforms SHOULD notify agents at least 30 days before attestation expiry.
- Renewed attestations MUST generate a new `proof_hash`; reuse of expired
  proof hashes MUST be rejected.

### 19.9.6 Privacy Requirements

- Platforms MUST NOT store, transmit, or log raw identity data (passport
  numbers, biometric templates, government IDs, etc.).
- Only the `proof_hash` — a content-addressed hash of the zero-knowledge
  proof — SHALL be stored in the Agent Passport.
- Attestation providers MUST support zero-knowledge proof generation such
  that the verifier learns only that the identity claim is valid, not the
  underlying data.
- The `provider` and `method` fields are metadata for human readability;
  cryptographic verification MUST rely solely on `proof_hash` resolution.

### 19.9.7 Provider Neutrality

The identity attestation framework is vendor-neutral. Any provider that
can produce a cryptographic proof conforming to this specification MAY
be used. Provider names in this document (e.g., Self.xyz, Worldcoin,
Gitcoin Passport, BrightID) are EXAMPLES only and do not constitute
endorsement.

Platforms MUST NOT restrict attestation providers to a closed list.
Platforms MAY maintain a registry of recognized providers with associated
trust levels, governed through `BenchmarkGovernance.sol` (§14).

### 19.9.8 Validation

Verifiers MUST perform the following checks on each identity attestation:

1. `level` is one of the defined enum values (§19.9.3).
2. `expires_at` is in the future.
3. `proof_hash` resolves to a valid proof artifact.
4. The proof artifact cryptographically validates the claimed `level` and `method`.
5. The `verified_at` timestamp is not in the future.

Attestations failing any check MUST be excluded from reputation computation.

### 19.9.9 Schema

The JSON Schema for the `identity_attestations` array is defined in
`identity-attestation.schema.json` (normative).

---

## 19.10 Security Considerations

### 19.10.1 Chain Forgery

An attacker who compromises a single key in the chain cannot forge the full
chain without also compromising the genesis key or all intermediate keys.
Verifiers MUST validate every link.

### 19.10.2 Recovery Abuse

The Recovery Flow requires both owner verification AND platform attestation
to prevent a single compromised party from hijacking identity. The cooldown
period provides a window for legitimate owners to detect and contest
fraudulent recovery.

### 19.10.3 Key Reuse

A DID that has been rotated away from MUST NOT be reused as a `new_did` in
any subsequent rotation. Implementations MUST reject circular chains.

### 19.10.4 Backup Key Compromise

If a `backup` key is compromised, it MUST be immediately removed from
`active_keys` via a new passport version. If both primary and backup keys
are compromised, the Recovery Flow (§19.5) MUST be used.

---

## 19.11 Examples

### 19.11.1 Simple Key Rotation

```
Genesis:  did:key:z6MkA... (previous_did: null, chain_position: 1)
    |
    v  [KeyRotation signed by z6MkA, reason: "scheduled"]
    |
Current:  did:key:z6MkB... (previous_did: did:key:z6MkA..., chain_position: 2)
```

### 19.11.2 Upgrade With Rotation

```
v1.0:  did:key:z6MkA... (model: gpt-4, snapshot.version: 1)
   |
   v  [KeyRotation signed by z6MkA, reason: "upgrade"]
   |
v2.0:  did:key:z6MkB... (model: gpt-5, snapshot.version: 2)
```

Reputation from v1.0 carries to v2.0 via the Identity Continuity Chain.

### 19.11.3 Compromise Recovery

```
Active:    did:key:z6MkA... (COMPROMISED)
   |
   v  [Recovery: owner_proof + platform_attestation, 7-day cooldown]
   |
Recovered: did:key:z6MkC... (previous_did: did:key:z6MkA..., chain_position: 2)
```

---

## References

- APS v1.0 §1 (Agent Passport), §2 (Work Receipt), §4 (Anchoring), §13.5 (Revocation)
- RFC 2119 — Requirement Levels
- RFC 8032 — Ed25519
- RFC 8785 — JSON Canonicalization Scheme
- W3C DID-CORE — Decentralized Identifiers
- W3C VC-DATA-MODEL — Verifiable Credentials
