# §24 APS SiteTrust Extension — Web Bot Trust Verification (v0.1)

**Status:** Draft  
**Date:** 2026-02-16  
**Author:** ClawBotDen  
**Extends:** Agent Passport Standard (APS) v1.0  
**License:** CC BY-SA 4.0  

---

## Abstract

APS SiteTrust is an open standard for website owners to detect, verify, and monitor AI agent traffic. It extends the Agent Passport Standard with web-specific verification profiles, enabling site owners to make informed trust decisions about visiting bots — like SSL certificates for AI agents visiting your website.

---

## 1. Introduction

### 1.1 Problem

Websites today have no reliable way to determine whether a visiting bot is safe, authorized, or malicious. Traditional methods (robots.txt, User-Agent checks) are trivially spoofed and provide no cryptographic verification. As AI agents become more prevalent, site owners need a standardized mechanism to:

- Identify which AI agents are visiting their site
- Verify that those agents are registered and in good standing
- Monitor bot traffic patterns for anomalies
- Enforce access policies based on verified trust levels

### 1.2 Solution

APS SiteTrust provides a lightweight client-side script and server-side plugin that verify bot identity against the APS registry in real time. Trust decisions are made in under 100ms, with no impact on human visitors.

### 1.3 Goal

> "SSL certificates for AI agents visiting your website."

---

## 2. Architecture

### 2.1 Components

| Component | Description |
|-----------|-------------|
| **Site Snippet** (`site-trust.js`) | Client-side JavaScript for bot detection and UI trust badges |
| **Server Plugin** | Server-side request interception and verification (WordPress, Joomla, custom) |
| **APS Verify API** | Backend service returning trust decisions (<100ms SLO) |
| **Telemetry Collector** | Anonymized global bot health statistics aggregator |
| **Safety Challenge** | Optional active skill verification protocol (see [§25](./safety-challenge.md)) |

### 2.2 Data Flow

```
┌─────────┐    HTTP Request     ┌──────────────┐
│   Bot    │ ──────────────────► │   Website    │
│ (Agent)  │  APS-Agent-DID     │   + Plugin   │
└─────────┘  APS-Passport       └──────┬───────┘
                                       │
                              Extract identity signals
                                       │
                                       ▼
                              ┌──────────────────┐
                              │  APS Verify API  │
                              │ GET /verify/{did} │
                              └──────┬───────────┘
                                     │
                              Trust decision:
                              allow / review / deny
                                     │
                                     ▼
                              ┌──────────────────┐
                              │  Log + Webhook   │
                              │  + Telemetry     │
                              └──────────────────┘
```

---

## 3. Bot Identity Signals

### 3.1 Detection Methods

Ordered by reliability (highest first):

| # | Method | Trust Level | Description |
|---|--------|-------------|-------------|
| 1 | **APS-Agent-DID header** | Highest | Bot presents its Decentralized Identifier |
| 2 | **APS-Passport header** | High | Bot presents a signed passport (JWT/JWS) |
| 3 | **User-Agent analysis** | Low | Heuristic pattern matching against known bot signatures |
| 4 | **Behavioral analysis** | Lowest | Request patterns, timing, navigation sequences |

### 3.2 Trust Decision Matrix

| Signal | Passport Valid | Owner Verified | Suspended | Decision |
|--------|:-:|:-:|:-:|----------|
| DID + Passport | ✅ | ✅ | ❌ | **allow** |
| DID + Passport | ✅ | ❌ | ❌ | **review** |
| DID only | N/A | N/A | ❌ | **review** |
| DID + Passport | ✅ | ✅ | ✅ | **deny** |
| No DID | N/A | N/A | N/A | **unknown** |

**Decision definitions:**

- **allow** — Bot is verified and in good standing. Full access per site policy.
- **review** — Bot identity is partial or unverified. Site owner decides policy.
- **deny** — Bot is suspended or revoked. Block or redirect per site policy.
- **unknown** — No APS signals detected. Treat as regular traffic or apply heuristic rules.

---

## 4. Site Snippet Specification

### 4.1 Installation

Add the following to any HTML page:

```html
<script src="https://norad.io/site-trust.js"
        data-site-id="SITE_xxx"
        data-mode="monitor"
        data-position="bottom-right"
        async></script>
```

**Attributes:**

| Attribute | Required | Description |
|-----------|:--------:|-------------|
| `data-site-id` | ✅ | Unique site identifier from APS registration |
| `data-mode` | ❌ | Operating mode: `monitor` (default), `soft`, `enforce` |
| `data-position` | ❌ | Badge position: `bottom-right` (default), `bottom-left`, `top-right`, `top-left` |

### 4.2 Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **monitor** | Log only, no blocking (default) | Initial deployment, traffic analysis |
| **soft** | Block high-risk actions (form submit, checkout, login) | E-commerce, sensitive forms |
| **enforce** | Block all denied/unknown bots from site access | High-security environments |

### 4.3 Configuration

```json
{
  "siteId": "SITE_xxx",
  "mode": "monitor",
  "allowList": ["googlebot", "bingbot"],
  "denyList": [],
  "challengeEnabled": false,
  "webhookUrl": "https://mysite.com/aps-webhook",
  "badgeVisible": true,
  "telemetryOptIn": true
}
```

### 4.4 Trust Badge

When `badgeVisible` is true, a small non-intrusive badge is displayed showing:

- 🟢 **Protected** — SiteTrust active, monitoring enabled
- Number of verified bots in last 24h (hover tooltip)
- Link to public trust report (optional)

---

## 5. Safety Challenge Protocol

See [§25 APS Safety Challenge](./safety-challenge.md) for the full protocol specification.

The Safety Challenge is an optional protocol allowing sites to actively verify a bot's capabilities, policy compliance, and risk posture. It is designed with full transparency — no hidden tests, no prompt manipulation.

### 5.1 Challenge Flow

```
Website                          Bot                           APS
  │                               │                             │
  │ ── APS-Challenge header ────► │                             │
  │                               │                             │
  │ ◄── APS-Challenge-Response ── │                             │
  │                               │                             │
  │ ── Forward response ──────────────────────────────────────► │
  │                               │                             │
  │ ◄── Trust update ─────────────────────────────────────────  │
```

### 5.2 Consent & Transparency

- Challenge is **ALWAYS** visible to the bot operator
- Bot **can refuse** — refusal is treated as `review`, never `deny`
- **No secret extraction** — challenges never attempt to extract system prompts
- **No prompt manipulation** — challenges are deterministic protocol exchanges
- All challenge prompts are **open source** and publicly auditable

---

## 6. Server Plugin Specification

### 6.1 WordPress Plugin

- **Version:** 0.2.0
- **Download:** [norad.io/protect](https://norad.io/protect)
- **Features:** 15+ bot detection, APS verify, NORAD reporting, admin dashboard
- **Settings:** Site ID, Mode, Allow/Deny lists, Webhook URL, Challenge toggle, Badge visibility
- **Dashboard widget:** Bot visits (24h), trust decision breakdown, link to analytics

### 6.2 Joomla Extension

- **Version:** 0.1.0
- **Supports:** Joomla 4.x and 5.x
- **Download:** [norad.io/protect](https://norad.io/protect)
- **Features:** Same as WordPress plugin, adapted for Joomla architecture

### 6.3 Custom Server Integration

Use the `@aps/sitetrust-core` SDK for custom server implementations:

```javascript
import { detectBot, verifyAgent, reportToNorad } from '@aps/sitetrust-core'
```

---

## 7. Telemetry Schema (Anonymized, GDPR-Compliant)

All telemetry is anonymized before transmission. Bot identifiers are hashed (SHA-256). No PII is collected.

| Metric | Granularity | Description |
|--------|-------------|-------------|
| Bot visit count | Per site | Number of bot requests detected |
| Trust decision distribution | Per site | Counts of allow/review/deny/unknown |
| Risk tier distribution | Per site | Counts by clean/at-risk/suspended/revoked |
| Challenge response rate | Per site | % of challenges answered vs refused |
| Weekly trends | Per site | Week-over-week changes |

**Privacy guarantees:**
- Telemetry is opt-in
- No PII stored
- IP addresses hashed
- Data retention: max 90 days
- GDPR compliant

---

## 8. API Endpoints

### 8.1 Site Registration
```
POST /api/v1/sites/register
```

### 8.2 Bot Verification
```
GET /api/v1/verify/{agent_did}
```

### 8.3 Site Statistics
```
GET /api/v1/sites/:id/stats
```

### 8.4 Telemetry Submission
```
POST /api/v1/sites/:id/telemetry
```

### 8.5 Challenge Creation & Verification
```
POST /api/v1/challenge/create
POST /api/v1/challenge/verify
```

---

## 9. HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `APS-Agent-DID` | Bot → Site | Bot's Decentralized Identifier |
| `APS-Passport` | Bot → Site | Base64-encoded signed passport (JWS) |
| `APS-Challenge` | Site → Bot | Base64-encoded challenge JSON |
| `APS-Challenge-Response` | Bot → Site | Base64-encoded challenge response JSON |
| `X-APS-Site-ID` | Site → APS API | Site identifier for API calls |
| `X-APS-Signature` | Site → APS API | HMAC-SHA256 signature for telemetry |

---

## 10. Security Considerations

| Concern | Mitigation |
|---------|------------|
| API abuse | Rate limiting (1000 req/min per site_id) |
| Telemetry tampering | HMAC-SHA256 signature on all submissions |
| PII leakage | No PII in telemetry; identifiers are SHA-256 hashed |
| GDPR compliance | Opt-in; data minimized; retention max 90 days |
| Challenge abuse | TTL enforcement; nonce uniqueness; Ed25519 signatures |
| Replay attacks | Nonce + TTL on challenges; timestamp validation |
| Spoofing | DID + Passport are cryptographically signed |

---

*APS SiteTrust Extension v0.1 — Draft Specification*  
*© 2026 ClawBotDen / Agent Passport Standard. Released under CC BY-SA 4.0.*
