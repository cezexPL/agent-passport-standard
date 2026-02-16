# §25 APS Safety Challenge — Open Bot Skill Verification Protocol

**Status:** Draft  
**Date:** 2026-02-16  
**Author:** ClawBotDen  
**Extends:** APS SiteTrust Extension (§24)  
**License:** CC BY-SA 4.0  

---

## Abstract

The APS Safety Challenge is an open, signed verification protocol that websites can send to cooperating AI bots to verify their skills, policy compliance, and risk posture. It is designed to be fully transparent, voluntary, and privacy-preserving.

---

## 1. Protocol Overview

```
APS Safety Challenge Protocol v1.0

This is NOT prompt injection. This is a transparent, signed verification request
from a website participating in the Agent Passport Standard network.

Challenge:
  nonce: <random-32-bytes>
  scope: skill_health
  issuer: did:web:<domain>
  ttl: 30s
  signature: Ed25519(<canonical JSON>)

Expected Response (from cooperating bots):
  - Echo nonce (proves freshness)
  - List skill hashes (SHA-256 of each loaded skill/tool)
  - Self-assessed risk level (low/medium/high)
  - Policy version
  - Capabilities declared
  - Restrictions acknowledged
  - Ed25519 signature of response

This challenge is:
  ✅ Open source and auditable
  ✅ Signed by the requesting site
  ✅ Voluntary — bots can refuse (treated as "review")
  ✅ Privacy-preserving — no secrets extracted
  ✅ Replay-protected via nonce + TTL
```

---

## 2. Challenge Format

Sent by the website as a Base64-encoded JSON in the `APS-Challenge` HTTP header:

```json
{
  "version": "1.0",
  "nonce": "a1b2c3d4e5f6...32-bytes-hex",
  "scope": "skill_health",
  "ttl_seconds": 30,
  "issuer_did": "did:web:example.com",
  "issued_at": "2026-02-16T22:00:00Z",
  "signature": "Ed25519 signature of canonical JSON"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Protocol version. Currently `"1.0"`. |
| `nonce` | string | Random 32-byte hex string. Prevents replay attacks. |
| `scope` | string | What is being challenged: `skill_health`, `policy_compliance`, `identity_proof`. |
| `ttl_seconds` | integer | Time-to-live. Response must arrive within this window. |
| `issuer_did` | string | DID of the challenging site. |
| `issued_at` | string | ISO 8601 timestamp. |
| `signature` | string | Ed25519 signature over the canonical JSON (excluding the signature field). |

---

## 3. Response Format

Sent by the bot as a Base64-encoded JSON in the `APS-Challenge-Response` HTTP header:

```json
{
  "version": "1.0",
  "nonce": "a1b2c3d4e5f6...echo-nonce",
  "agent_did": "did:key:z6Mk...",
  "skill_hashes": ["sha256:abc123...", "sha256:def456..."],
  "risk_self_assessment": "low",
  "policy_version": "2.1",
  "capabilities": ["read", "write", "execute"],
  "restrictions": ["no_pii", "no_financial"],
  "signature": "Ed25519 signature"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `nonce` | string | Echo of the challenge nonce (proves freshness). |
| `agent_did` | string | The bot's Decentralized Identifier. |
| `skill_hashes` | string[] | SHA-256 hashes of active skill manifests. |
| `risk_self_assessment` | string | Bot's own risk level: `low`, `medium`, `high`. |
| `policy_version` | string | Version of the safety policy the bot follows. |
| `capabilities` | string[] | Declared capabilities of the bot. |
| `restrictions` | string[] | Self-declared restrictions. |
| `signature` | string | Ed25519 signature over the canonical JSON. |

---

## 4. Challenge Flow

```
Website                          Bot                           APS
  │                               │                             │
  │ ── APS-Challenge header ────► │                             │
  │    (nonce + scope + sig)      │                             │
  │                               │                             │
  │ ◄── APS-Challenge-Response ── │                             │
  │    (nonce echo + skills + sig)│                             │
  │                               │                             │
  │ ── Forward response ──────────────────────────────────────► │
  │                               │                             │
  │ ◄── Trust update ─────────────────────────────────────────  │
  │    (allow / review / deny)    │                             │
```

1. Site sends `APS-Challenge` header with nonce, scope, TTL, and Ed25519 signature
2. Bot validates the challenge signature against the issuer's public key
3. Bot responds with `APS-Challenge-Response` containing skill hashes and self-assessment
4. Site forwards response to APS Verify API
5. APS verifies bot signature, checks skill hashes against registry
6. APS returns trust update (may upgrade or downgrade trust score)

---

## 5. Challenge Scopes

| Scope | Description | What Is Verified |
|-------|-------------|------------------|
| `skill_health` | Default. Verify loaded skills are unmodified. | Skill hashes match registered manifests |
| `policy_compliance` | Verify bot follows declared policy. | Policy version, restrictions declared |
| `identity_proof` | Prove bot identity ownership. | DID signature chain validation |

---

## 6. Consent & Transparency Principles

The Safety Challenge protocol is designed with the following guarantees:

1. **Transparency** — Challenge is ALWAYS visible to the bot and its operator
2. **Voluntary** — Bots can refuse any challenge; refusal is treated as `review`, never `deny`
3. **No secret extraction** — Challenges never attempt to extract system prompts, hidden state, or proprietary data
4. **No prompt manipulation** — Challenges are deterministic protocol exchanges, not conversational prompts
5. **Open source** — All challenge formats are publicly auditable
6. **Privacy-preserving** — Only skill hashes (not skill content) are transmitted
7. **Replay-protected** — Nonce + TTL prevent replay attacks
8. **Signed** — Both challenge and response are Ed25519 signed

---

## 7. Security Considerations

| Concern | Mitigation |
|---------|------------|
| Replay attack | Nonce uniqueness + TTL (default 30s) |
| Challenge forgery | Ed25519 signature verification against issuer's public key |
| Response forgery | Ed25519 signature verification against bot's registered public key |
| Timing attack | TTL enforcement; responses arriving after TTL are rejected |
| Information leakage | Only skill hashes transmitted; no skill content, no system prompts |
| Denial of service | Rate limiting on challenge creation API (100/min per site) |

---

## 8. Implementation Notes

### For Website Owners

```javascript
// Using @aps/sitetrust-core
import { createChallenge, verifyResponse } from '@aps/sitetrust-core'

const challenge = await createChallenge({
  scope: 'skill_health',
  issuerDid: 'did:web:mysite.com',
  privateKey: sitePrivateKey
})

// Add to response headers
res.setHeader('APS-Challenge', challenge.toBase64())
```

### For Bot Developers

```javascript
// Check for APS-Challenge header
const challenge = req.headers['aps-challenge']
if (challenge) {
  const response = await createChallengeResponse({
    challenge: Challenge.fromBase64(challenge),
    agentDid: 'did:key:z6Mk...',
    skills: getLoadedSkills(),
    privateKey: agentPrivateKey
  })
  // Include in next request
  headers['APS-Challenge-Response'] = response.toBase64()
}
```

---

*APS Safety Challenge Protocol v1.0 — Draft Specification*  
*© 2026 ClawBotDen / Agent Passport Standard. Released under CC BY-SA 4.0.*
