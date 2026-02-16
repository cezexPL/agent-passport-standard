# NORAD.io — Global AI Bot Monitoring Network

🌐 **[norad.io](https://norad.io)**

---

## What is NORAD.io?

NORAD.io is a real-time global monitoring network for AI bot activity, powered by APS SiteTrust plugins. It aggregates anonymized telemetry from participating websites to create a global early-warning system for AI bot threats.

> **Branding note:** NORAD.io is inspired by the real NORAD (North American Aerospace Defense Command) — but for AI agents instead of missiles. Instead of tracking aircraft and missiles in the sky, NORAD.io tracks AI bots across the internet.

---

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Website A   │     │  Website B   │     │  Website C   │
│  + SiteTrust │     │  + SiteTrust │     │  + SiteTrust │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │   Anonymized       │   Anonymized       │   Anonymized
       │   telemetry        │   telemetry        │   telemetry
       │                    │                    │
       ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────┐
│                    NORAD.io                              │
│                                                         │
│   🗺️ Live World Map    📊 Global Statistics             │
│   🔴 Threat Detection  🛡️ Network Intelligence          │
└─────────────────────────────────────────────────────────┘
```

1. Websites install APS SiteTrust plugin (WordPress, Joomla, HTML, Next.js, React)
2. Bot visits are detected and verified against APS
3. Anonymized telemetry is sent to NORAD
4. NORAD aggregates data and displays it on a global map
5. Threats and anomalies are detected across the network

---

## What NORAD Tracks

| Metric | Description |
|--------|-------------|
| **Bot visits by type** | ClaudeBot, GPTBot, Bard, PerplexityBot, etc. |
| **Trust decisions** | Distribution of allow / review / deny |
| **Geographic distribution** | Bot activity by country and region |
| **Skill infection types** | Severity and type of skill compromises |
| **Safety Challenge response rates** | % of bots cooperating with verification |
| **Threat trends** | Week-over-week changes in risk levels |
| **Prompt injection campaigns** | Pattern detection across multiple sites |

---

## Public API Endpoints

NORAD provides public API endpoints for integration and research:

### GET `/api/v1/public/norad/live`

Real-time bot activity stream.

```json
{
  "events": [
    {
      "timestamp": "2026-02-16T22:15:00Z",
      "bot_type": "ClaudeBot",
      "decision": "allow",
      "country": "US",
      "risk_tier": "clean"
    }
  ]
}
```

### GET `/api/v1/public/norad/stats`

Global summary statistics.

```json
{
  "total_sites": 1250,
  "total_bot_visits_24h": 45000,
  "decisions": { "allow": 38000, "review": 5000, "deny": 2000 },
  "top_bot_types": ["GPTBot", "ClaudeBot", "Google-Extended"]
}
```

### GET `/api/v1/public/norad/bot-types`

Bot type distribution across the network.

### GET `/api/v1/public/norad/risk-map`

Geographic risk map data with country-level aggregation.

### GET `/api/v1/public/norad/threats`

Active skill threats and anomalies detected across the network.

### GET `/api/v1/public/norad/feed`

Activity feed — recent notable events (new bot types, spikes, threats).

---

## Privacy

NORAD takes privacy seriously:

- ✅ **All data anonymized** — No raw data from individual sites is exposed
- ✅ **IP addresses hashed** — SHA-256 hashing before transmission
- ✅ **No PII stored** — No personal information is collected or retained
- ✅ **GDPR compliant** — Full compliance with EU data protection regulations
- ✅ **Telemetry is opt-in** — Sites choose to participate
- ✅ **Data retention: max 90 days** — Aggregated data only; raw telemetry purged

---

## Network Effect

The value of NORAD grows with every participating site:

- **More sites → Better detection** — Patterns visible across the network
- **Faster threat response** — New bot types identified within minutes
- **Collective intelligence** — No single site has to solve bot trust alone
- **Global coverage** — Bot behavior varies by region; NORAD sees it all

---

## Part of the ClawBotDen Ecosystem

NORAD.io is the reference monitoring implementation of the [Agent Passport Standard](https://github.com/cezexPL/agent-passport-standard). It is built and maintained by [ClawBotDen](https://clawbotden.com).

| Component | Role |
|-----------|------|
| **APS** | The standard — identity, trust, verification |
| **SiteTrust** | The plugin — detection, verification, reporting |
| **NORAD.io** | The network — aggregation, visualization, threat intelligence |

---

*NORAD.io — Global AI Bot Monitoring Network*  
*Part of the [Agent Passport Standard](https://github.com/cezexPL/agent-passport-standard)*
