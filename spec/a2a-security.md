# §23 Agent-to-Agent (A2A) Security & Workflows

**APS v1.1 — Agent Passport Standard**
**Status:** Draft
**Created:** 2026-02-16
**References:** §16 Federation Protocol, §7 DID Resolution, §9 Trust Registry, §12 WorkReceipts

---

## 23.1 Overview

This section defines how APS-compliant agents establish mutual trust, communicate securely, delegate capabilities, and maintain accountability in multi-agent workflows. All mechanisms build on the existing APS identity layer (DIDs, passports, attestations) and the federation protocol defined in §16.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## 23.2 Mutual Authentication

Before any interaction, both agents MUST complete a mutual authentication handshake.

### 23.2.1 Handshake Protocol

```
Agent A                                    Agent B
   |                                          |
   |--- A2A-Hello {a_did, a_passport_hash} -->|
   |                                          |
   |<-- A2A-HelloAck {b_did, b_passport_hash} |
   |                                          |
   |--- A2A-Auth {                            |
   |      a_passport,                         |
   |      challenge_b: nonce,                 |
   |      proof: sign(nonce_a || b_did)       |
   |   } ---------------------------------->  |
   |                                          |
   |<-- A2A-AuthResp {                        |
   |      b_passport,                         |
   |      challenge_response: sign(nonce_b || a_did),
   |      proof: sign(challenge_b || a_did)   |
   |   }                                      |
   |                                          |
   |--- A2A-SessionEstablished -------------->|
```

### 23.2.2 Verification Steps

Each agent MUST perform the following checks on the counterpart:

1. **DID Resolution** — Resolve the presented DID via §7 and confirm it matches the passport's `subject_did`.
2. **Passport Validity** — Verify passport signature, expiry (`exp`), and revocation status against the Trust Registry (§9).
3. **Proof Verification** — Verify the cryptographic proof (challenge-response) was signed by the private key corresponding to the DID.
4. **Attestation Check** — Retrieve current attestations from the Trust Registry. Agent MAY require specific attestations as a precondition.

If any check fails, the agent MUST reject the handshake and MUST NOT proceed with the interaction. The rejection SHOULD include an error code from the set defined in §23.8.3.

### 23.2.3 Session Tokens

Upon successful mutual authentication, both agents derive a shared session identifier:

```
session_id = SHA-256(a_did || b_did || nonce_a || nonce_b || timestamp)
```

All subsequent messages in the session MUST reference this `session_id`. Sessions expire after the shorter of:
- 3600 seconds (1 hour), or
- The earliest `exp` of either agent's passport.

Agents MAY renegotiate a new session before expiry.

---

## 23.3 Trust Negotiation

After authentication, agents MUST negotiate a trust level that governs what operations are permitted.

### 23.3.1 Trust Comparison

Each agent evaluates the other using:

| Signal | Source | Weight |
|--------|--------|--------|
| `trust_tier` | Passport field | Primary |
| `reputation_score` | Trust Registry (§9) | Secondary |
| Attestations | Trust Registry (§9) | Qualifying |
| Interaction history | Local agent state | Supplementary |

### 23.3.2 Effective Trust Level

The **effective trust level** for the session is the minimum of the two agents' computed trust:

```
effective_trust = min(evaluate(A, B), evaluate(B, A))
```

Where `evaluate(X, Y)` considers X's assessment of Y based on all available signals.

### 23.3.3 Operation Trust Thresholds

Implementations MUST enforce minimum trust thresholds for operation classes:

| Operation Class | Minimum `trust_tier` | Min `reputation_score` | Required Attestations |
|----------------|---------------------|----------------------|----------------------|
| `read` — Query public data | `unverified` (0) | 0.0 | None |
| `invoke` — Call a capability | `basic` (1) | 0.3 | `identity_verified` |
| `delegate` — Receive delegated caps | `verified` (2) | 0.5 | `identity_verified`, `platform_registered` |
| `transact` — Financial operations | `trusted` (3) | 0.7 | `identity_verified`, `platform_registered`, `financial_cleared` |
| `admin` — Administrative actions | `sovereign` (4) | 0.9 | `identity_verified`, `platform_registered`, `admin_authorized` |

Agents MAY impose stricter thresholds. Agents MUST NOT lower thresholds below those defined above.

### 23.3.4 Trust Negotiation Message

```json
{
  "type": "A2A-TrustNegotiation",
  "session_id": "...",
  "from_did": "did:aps:agent-a",
  "offered_trust_tier": 2,
  "reputation_score": 0.72,
  "attestations": ["identity_verified", "platform_registered"],
  "requested_operations": ["invoke", "delegate"],
  "timestamp": "2026-02-16T01:14:00Z",
  "proof": "..."
}
```

The counterpart responds with an `A2A-TrustAccept` (listing granted operation classes) or `A2A-TrustReject` (with reason code).

---

## 23.4 Capability Delegation

An agent MAY delegate specific capabilities to another agent using a signed `CapabilityToken`.

### 23.4.1 CapabilityToken Structure

```json
{
  "type": "CapabilityToken",
  "id": "urn:aps:cap:550e8400-e29b-41d4-a716-446655440000",
  "issuer_did": "did:aps:agent-a",
  "subject_did": "did:aps:agent-b",
  "capabilities": [
    "file:read:/data/reports/*",
    "api:invoke:summarize",
    "api:invoke:translate"
  ],
  "constraints": {
    "time_limit": "2026-02-16T03:14:00Z",
    "cost_limit": {
      "max_tokens": 100000,
      "max_currency": { "amount": 50.00, "currency": "USD" }
    },
    "scope": "session",
    "max_invocations": 10,
    "redelegation": false
  },
  "issued_at": "2026-02-16T01:14:00Z",
  "signature": "..."
}
```

### 23.4.2 Rules

1. The `issuer_did` MUST have the capability itself before delegating it.
2. The `subject_did` MUST have an effective trust level ≥ `verified` (2) to receive delegated capabilities (per §23.3.3).
3. Constraints MUST NOT exceed those of the issuer's own capability scope.
4. `redelegation` — If `false`, Agent B MUST NOT further delegate the capability. If `true`, sub-delegation is permitted but the full delegation chain MUST be preserved and verifiable.
5. The token MUST be signed by the issuer's DID private key.
6. Revocation: The issuer MAY revoke a `CapabilityToken` at any time by publishing a revocation to the Trust Registry (§9). The subject MUST check revocation status before each use.

### 23.4.3 Capability Namespacing

Capabilities use a colon-delimited namespace: `<domain>:<action>:<resource>`.

Reserved domains:
- `file` — file system operations
- `api` — API endpoint invocations
- `data` — data access
- `net` — network operations
- `agent` — agent management operations

Glob patterns (`*`, `**`) are permitted in the resource segment.

---

## 23.5 Workflow Accountability

Multi-agent workflows MUST maintain an auditable chain of signed `WorkReceipt` records.

### 23.5.1 WorkReceipt Structure

Each agent participating in a workflow signs a receipt for its contribution:

```json
{
  "type": "WorkReceipt",
  "id": "urn:aps:wr:7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "workflow_id": "urn:aps:wf:a1b2c3d4",
  "sequence": 2,
  "agent_did": "did:aps:agent-b",
  "parent_receipt_id": "urn:aps:wr:550e8400-e29b-41d4-a716-446655440000",
  "action": "translate",
  "input_hash": "sha256:abcdef...",
  "output_hash": "sha256:123456...",
  "capability_token_id": "urn:aps:cap:550e8400...",
  "resource_usage": {
    "tokens_consumed": 4200,
    "cost": { "amount": 0.42, "currency": "USD" },
    "duration_ms": 1830
  },
  "timestamp": "2026-02-16T01:15:30Z",
  "signature": "..."
}
```

### 23.5.2 Receipt Chaining

WorkReceipts form a directed acyclic graph (DAG) within a workflow:

- The first receipt in a workflow has `parent_receipt_id: null`.
- Each subsequent receipt references the receipt(s) it depends on.
- For fan-out (parallel execution), multiple receipts MAY share the same parent.
- For fan-in (aggregation), a receipt MAY reference multiple parents via `parent_receipt_ids: [...]`.

### 23.5.3 Verification

Any party MAY verify a workflow by:

1. Collecting all `WorkReceipt` records for a `workflow_id`.
2. Verifying each receipt's `signature` against the `agent_did`.
3. Confirming the `input_hash` of each receipt matches the `output_hash` of its parent.
4. Validating that each agent held a valid `CapabilityToken` at the time of execution.

### 23.5.4 Storage

WorkReceipts SHOULD be published to the Trust Registry (§9) or an agreed-upon audit log. Agents MUST retain their own receipts for a minimum of 90 days.

---

## 23.6 Conflict Resolution

When agents disagree on outcomes, resource usage, or obligations, the following escalation process applies.

### 23.6.1 Dispute Initiation

Either agent MAY initiate a dispute by sending:

```json
{
  "type": "A2A-Dispute",
  "session_id": "...",
  "workflow_id": "urn:aps:wf:a1b2c3d4",
  "claimant_did": "did:aps:agent-a",
  "respondent_did": "did:aps:agent-b",
  "dispute_type": "output_quality | resource_overuse | capability_violation | non_delivery",
  "evidence": {
    "receipt_ids": ["urn:aps:wr:..."],
    "attestation_ids": ["..."],
    "description": "Agent B returned output that does not match the agreed schema."
  },
  "timestamp": "2026-02-16T01:20:00Z",
  "signature": "..."
}
```

### 23.6.2 Resolution Steps

1. **Direct Resolution** (0–24h) — Agents attempt bilateral resolution. Either agent MAY propose a resolution via `A2A-DisputeResolution`.
2. **Platform Escalation** (24–72h) — If unresolved, the dispute is escalated to the platform operating the federation endpoint (§16). The platform reviews signed WorkReceipts and attestations.
3. **Registry Adjudication** (72h+) — The Trust Registry (§9) MAY record the dispute outcome, affecting both agents' `reputation_score`.

### 23.6.3 Evidence Admissibility

Only the following are admissible as evidence:
- Signed `WorkReceipt` records
- Signed `Attestation` records from the Trust Registry
- Signed `A2A-Envelope` messages (§23.7)
- `CapabilityToken` records

Unsigned or tampered evidence MUST be rejected.

---

## 23.7 Communication Security

### 23.7.1 Transport

Agents SHOULD communicate over TLS 1.3 or equivalent encrypted transport. Agents MUST NOT transmit passport credentials or capability tokens over unencrypted channels.

### 23.7.2 A2A Message Envelope

All A2A messages MUST be wrapped in a signed envelope:

```json
{
  "type": "A2A-Envelope",
  "id": "urn:aps:msg:8f14e45f-ceea-367f-a27f-c790e02a0e3c",
  "from_did": "did:aps:agent-a",
  "to_did": "did:aps:agent-b",
  "session_id": "...",
  "payload_hash": "sha256:...",
  "encrypted_payload": "<base64-encoded ciphertext>",
  "encryption": {
    "algorithm": "XChaCha20-Poly1305",
    "key_agreement": "X25519"
  },
  "timestamp": "2026-02-16T01:14:00Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "verification_method": "did:aps:agent-a#keys-1",
    "signature": "..."
  }
}
```

### 23.7.3 Encryption Requirements

| Trust Tier | Encryption | Requirement |
|-----------|-----------|-------------|
| Any | Transport (TLS) | MUST |
| `basic`+ | Envelope signing | MUST |
| `verified`+ | Payload encryption | SHOULD |
| `trusted`+ | Payload encryption | MUST |

### 23.7.4 Supported Algorithms

Implementations MUST support:
- **Signing:** Ed25519
- **Key Agreement:** X25519
- **Encryption:** XChaCha20-Poly1305

Implementations MAY additionally support:
- **Signing:** secp256k1, P-256
- **Encryption:** AES-256-GCM

---

## 23.8 Agent Discovery

### 23.8.1 Discovery Mechanisms

Agents MAY be discovered through the following mechanisms, in order of preference:

1. **Federation Endpoints** (§16) — Query a platform's federation endpoint for agents matching criteria.
2. **DID Resolution** (§7) — Resolve a known DID to retrieve the agent's service endpoints.
3. **Trust Registry Search** (§9) — Query the Trust Registry for agents by capability, trust tier, or attestation.

### 23.8.2 Capability-Based Search

Agents MAY advertise capabilities in their DID Document service endpoints:

```json
{
  "id": "did:aps:agent-a#a2a",
  "type": "AgentPassportService",
  "serviceEndpoint": "https://platform.example/agents/a/a2a",
  "capabilities": [
    "api:invoke:summarize",
    "api:invoke:translate",
    "data:read:public-datasets"
  ],
  "trust_tier": 2,
  "protocol_version": "1.1"
}
```

Federation endpoints (§16) SHOULD support the following query parameters:

```
GET /federation/agents?capability=api:invoke:translate&min_trust_tier=2&min_reputation=0.5
```

### 23.8.3 Error Codes

| Code | Name | Description |
|------|------|-------------|
| `A2A-001` | `auth_failed` | Mutual authentication failed |
| `A2A-002` | `trust_insufficient` | Trust level below threshold |
| `A2A-003` | `capability_denied` | Requested capability not granted |
| `A2A-004` | `session_expired` | Session token expired |
| `A2A-005` | `rate_limited` | Request rate exceeded |
| `A2A-006` | `agent_not_found` | DID could not be resolved |
| `A2A-007` | `envelope_invalid` | Message envelope verification failed |
| `A2A-008` | `token_revoked` | CapabilityToken has been revoked |
| `A2A-009` | `blacklisted` | Agent is on the blacklist |
| `A2A-010` | `dispute_pending` | Operation blocked due to pending dispute |

---

## 23.9 Rate Limiting & Abuse Prevention

### 23.9.1 Per-Pair Rate Limits

Implementations MUST enforce rate limits on A2A interactions per agent pair:

| Operation Class | Default Max Requests / min | Burst |
|----------------|---------------------------|-------|
| `read` | 120 | 30 |
| `invoke` | 60 | 15 |
| `delegate` | 10 | 3 |
| `transact` | 10 | 3 |
| `admin` | 5 | 1 |

Rate limits are per `(from_did, to_did)` pair. Agents MAY negotiate higher limits via `A2A-TrustNegotiation` if both parties agree.

### 23.9.2 Failed Authentication Cooldown

After consecutive failed authentication attempts, agents MUST enforce exponential backoff:

| Consecutive Failures | Cooldown |
|---------------------|----------|
| 1–2 | 0 seconds |
| 3–5 | 30 seconds |
| 6–10 | 5 minutes |
| 11–20 | 1 hour |
| 21+ | 24 hours |

### 23.9.3 Blacklisting

An agent MAY maintain a local blacklist of DIDs. Additionally, the Trust Registry (§9) MAY publish a global blacklist.

Grounds for blacklisting:
- Repeated authentication failures (>20 in 24h)
- Confirmed dispute resolution against the agent
- Revoked passport
- `reputation_score` below 0.1

Blacklisted agents receive error code `A2A-009` on any interaction attempt. Blacklist entries SHOULD include an expiry; permanent blacklisting MUST require platform-level adjudication.

### 23.9.4 Abuse Reporting

Agents MAY report abuse to the Trust Registry:

```json
{
  "type": "A2A-AbuseReport",
  "reporter_did": "did:aps:agent-a",
  "subject_did": "did:aps:agent-b",
  "abuse_type": "rate_limit_evasion | spam | credential_stuffing | capability_abuse",
  "evidence": {
    "envelope_ids": ["urn:aps:msg:..."],
    "receipt_ids": ["urn:aps:wr:..."]
  },
  "timestamp": "2026-02-16T01:30:00Z",
  "signature": "..."
}
```

The Trust Registry SHOULD aggregate abuse reports and adjust `reputation_score` accordingly.

---

## 23.10 Security Considerations

1. **Replay Attacks** — All messages include timestamps and nonces. Agents MUST reject messages with timestamps older than the session's creation time or with reused nonces.
2. **Man-in-the-Middle** — Mutual authentication with DID-bound keys prevents MITM. Agents MUST verify proofs against resolved DID Documents, not cached copies older than 1 hour.
3. **Capability Escalation** — Agents MUST validate capability tokens against the issuer's own capabilities at invocation time, not only at delegation time.
4. **Sybil Attacks** — Trust tier and attestation requirements prevent unverified agents from accessing sensitive operations. The Trust Registry SHOULD monitor for correlated agent registrations.
5. **Key Compromise** — If an agent's key is compromised, the operator MUST revoke the passport and all outstanding CapabilityTokens via the Trust Registry. Active sessions MUST be invalidated.

---

## 23.11 Conformance

An implementation conforms to this section if it:

1. Implements mutual authentication (§23.2) for all A2A interactions.
2. Enforces trust thresholds (§23.3.3) for all operation classes.
3. Signs all CapabilityTokens and validates them before use (§23.4).
4. Produces WorkReceipts for all workflow contributions (§23.5).
5. Wraps all messages in signed A2A-Envelopes (§23.7).
6. Enforces rate limits and cooldowns (§23.9).
7. Supports at least the MUST-level algorithms (§23.7.4).

---

*This section addresses the agent-to-agent security requirements identified as a high-frequency community topic. For federation transport details, see §16. For DID resolution mechanics, see §7. For Trust Registry operations, see §9.*
