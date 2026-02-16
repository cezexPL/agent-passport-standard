# APS SiteTrust — Integration Plugins

Integrate APS SiteTrust into your website to detect, verify, and monitor AI bot traffic. Choose the plugin that matches your platform.

---

## WordPress Plugin

**Version:** 0.2.0  
**Download:** [norad.io/protect](https://norad.io/protect)  
**Source:** Private (ClawBotDen repository)  
**Requires:** WordPress 5.8+, PHP 7.4+

### Installation

1. Download the plugin ZIP from [norad.io/protect](https://norad.io/protect)
2. Go to `wp-admin → Plugins → Add New → Upload Plugin`
3. Upload the ZIP file and click **Install Now**
4. Click **Activate**

### Settings

Navigate to `Settings → APS SiteTrust`:

| Setting | Type | Description |
|---------|------|-------------|
| Site ID | Text | Your `SITE_xxx` identifier |
| Mode | Dropdown | `monitor` / `soft` / `enforce` |
| Allow List | Textarea | Bot identifiers to always allow (one per line) |
| Deny List | Textarea | Bot identifiers to always deny (one per line) |
| Webhook URL | URL | Endpoint for decision event notifications |
| Challenge Enabled | Checkbox | Enable Safety Challenge protocol |
| Badge Visible | Checkbox | Show trust badge on frontend |
| Telemetry Opt-In | Checkbox | Send anonymized stats to APS/NORAD |

### Features

- **15+ AI bot type detection** — ClaudeBot, GPTBot, Bard, Perplexity, and more
- **APS identity verification** — Cryptographic verification in <100ms
- **NORAD reporting** — Anonymized telemetry to global monitoring network
- **Admin dashboard widget** — Bot visits (24h), trust decision pie chart
- **Dedicated analytics page** — `Tools → APS SiteTrust Analytics`
  - Full decision log with filters (date, decision, bot DID)
  - Charts: visits over time, trust distribution, risk trends
  - Export to CSV
  - Challenge log (if enabled)

---

## Joomla Extension

**Version:** 0.1.0  
**Download:** [norad.io/protect](https://norad.io/protect)  
**Supports:** Joomla 4.x and 5.x  
**Requires:** PHP 7.4+

### Installation

1. Download the extension package from [norad.io/protect](https://norad.io/protect)
2. Go to `System → Extensions → Install`
3. Upload the package and install

### Settings

Navigate to `Components → APS SiteTrust`:

- Same settings as WordPress plugin (Site ID, Mode, Allow/Deny lists, etc.)
- Joomla-native admin panel integration
- System plugin for request interception

### Features

- Same detection and verification capabilities as WordPress plugin
- Joomla event system integration
- Compatible with Joomla's access control system

---

## HTML Snippet (Any Website)

For any website, add the SiteTrust snippet before `</body>`:

```html
<script src="https://norad.io/site-trust.js" 
        data-site-id="YOUR_SITE_ID" 
        data-mode="monitor" 
        async></script>
```

### Attributes

| Attribute | Required | Default | Description |
|-----------|:--------:|---------|-------------|
| `data-site-id` | ✅ | — | Your site identifier |
| `data-mode` | ❌ | `monitor` | `monitor` / `soft` / `enforce` |
| `data-position` | ❌ | `bottom-right` | Badge position |

### What It Does

- Displays a trust badge showing SiteTrust protection status
- Reports bot visits to NORAD (anonymized)
- Works alongside server-side plugins or standalone

---

## Next.js — `@aps/sitetrust-next`

### Installation

```bash
npm install @aps/sitetrust-next
```

### Middleware Integration

```typescript
// middleware.ts
import { withSiteTrust } from '@aps/sitetrust-next'

export default withSiteTrust({
  siteId: 'YOUR_SITE_ID',
  mode: 'monitor', // 'monitor' | 'soft' | 'enforce'
})
```

### Components

**TrustBadge** — Displays SiteTrust protection badge:

```tsx
import { TrustBadge } from '@aps/sitetrust-next'

export default function Layout({ children }) {
  return (
    <>
      {children}
      <TrustBadge position="bottom-right" />
    </>
  )
}
```

**NoradWidget** — Live bot activity feed:

```tsx
import { NoradWidget } from '@aps/sitetrust-next'

// Shows real-time bot detections on your site
<NoradWidget siteId="YOUR_SITE_ID" limit={10} />
```

---

## React — `@aps/sitetrust-react`

### Installation

```bash
npm install @aps/sitetrust-react
```

### SiteTrustProvider

Wrap your app with the provider:

```tsx
import { SiteTrustProvider, TrustBadge } from '@aps/sitetrust-react'

function App() {
  return (
    <SiteTrustProvider siteId="YOUR_SITE_ID" mode="monitor">
      <YourApp />
      <TrustBadge />
    </SiteTrustProvider>
  )
}
```

### Components

| Component | Description |
|-----------|-------------|
| `SiteTrustProvider` | Context provider, configures SiteTrust for the app |
| `TrustBadge` | Displays protection status badge |
| `BotActivityFeed` | Shows recent bot detections |

### Hooks

| Hook | Description |
|------|-------------|
| `useSiteTrust()` | Access SiteTrust context (stats, config, status) |
| `useNoradFeed()` | Subscribe to real-time NORAD activity feed |

### Example

```tsx
import { useSiteTrust, useNoradFeed } from '@aps/sitetrust-react'

function Dashboard() {
  const { stats, isProtected } = useSiteTrust()
  const { events } = useNoradFeed({ limit: 20 })

  return (
    <div>
      <p>Bot visits today: {stats.totalVisits}</p>
      <p>Verified: {stats.verified} | Denied: {stats.denied}</p>
      {events.map(e => (
        <div key={e.id}>{e.botType} — {e.decision}</div>
      ))}
    </div>
  )
}
```

---

## Core SDK — `@aps/sitetrust-core`

The core library used by all plugins and frameworks.

### Installation

```bash
npm install @aps/sitetrust-core
```

### API

```typescript
import { detectBot, verifyAgent, reportToNorad } from '@aps/sitetrust-core'

// Detect if a request is from a bot
const detection = detectBot(request)
// → { isBot: true, botType: 'ClaudeBot', confidence: 0.95, signals: [...] }

// Verify a detected bot against APS registry
const verification = await verifyAgent(detection.agentDid)
// → { decision: 'allow', passportValid: true, ownerVerified: true, riskTier: 'clean' }

// Report to NORAD (anonymized)
await reportToNorad({
  siteId: 'YOUR_SITE_ID',
  botType: detection.botType,
  decision: verification.decision,
  // IP is automatically hashed, no PII sent
})
```

### Detected Bot Types (15+)

| Bot | User-Agent Pattern |
|-----|--------------------|
| ClaudeBot | `ClaudeBot/1.0` |
| GPTBot | `GPTBot/1.0` |
| Google-Extended | `Google-Extended` |
| Bard | `Google-Bard` |
| PerplexityBot | `PerplexityBot` |
| Cohere | `cohere-ai` |
| Meta-ExternalAgent | `Meta-ExternalAgent` |
| Bytespider | `Bytespider` |
| CCBot | `CCBot` |
| And more... | See source for full list |

---

## Getting a Site ID

1. Visit [norad.io/protect](https://norad.io/protect)
2. Register your domain
3. Receive your `SITE_xxx` identifier
4. Install the plugin for your platform

---

*APS SiteTrust Plugins — Part of the [Agent Passport Standard](https://github.com/cezexPL/agent-passport-standard)*
