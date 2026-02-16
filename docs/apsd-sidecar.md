# APS Daemon Sidecar (`apsd`)

> **Spec Reference**: This document describes the reference implementation of an APS-compliant daemon sidecar, as defined in APS sections 4 (Identity), 7 (Snapshots), 12 (Chain Anchoring), and 19 (Security Scanning).

## Overview

`apsd` is a lightweight Go service that runs alongside any AI agent as a Docker sidecar. It automates the full APS lifecycle:

- **Identity**: Generates Ed25519 keypairs and DID:key identifiers
- **Registration**: Registers the agent on a compliant registry
- **Snapshots**: Continuously monitors agent artifacts (SOUL.md, skills, container image) and computes integrity hashes
- **Anchoring**: Publishes snapshot hashes on-chain for tamper-proof verification
- **Security Scanning**: Integrates with sandbox orchestrators to scan prompts and skills
- **Kill Switch**: Provides local suspend/resume capability per APS §16

## Architecture

```
┌─────────────────────────────────────────┐
│            Docker Compose               │
│                                         │
│  ┌───────────┐      ┌───────────────┐   │
│  │  Agent     │      │   apsd        │   │
│  │           │  ro   │               │   │
│  │ /bot/     │◄──────│ • keygen      │   │
│  │  SOUL.md  │       │ • snapshots   │   │
│  │  skills/  │       │ • health loop │   │
│  └───────────┘       │ • API :8099   │   │
│                      └───────┬───────┘   │
└──────────────────────────────┼───────────┘
                               │
                    ┌──────────▼──────────┐
                    │  APS Registry +     │
                    │  Chain Anchor       │
                    └─────────────────────┘
```

## Identity Generation (APS §4)

On first startup, `apsd` generates an Ed25519 keypair and derives a `did:key` identifier using the multicodec format:

```
did:key:z<base58btc(0xed01 || public_key)>
```

The identity is persisted at `/data/identity.json` and reused across restarts.

## Snapshot Lifecycle (APS §7)

A snapshot captures the integrity state of an agent:

| Field | Source | Hash Algorithm |
|-------|--------|---------------|
| `soul_hash` | SOUL.md file | SHA-256 |
| `skills_hash` | All files in skills/ (sorted, concatenated) | SHA-256 |
| `image_hash` | Container image digest (when Docker socket available) | As-is |

The health loop runs at a configurable interval (default: 1 hour):
1. Compute current snapshot
2. Compare with previous snapshot
3. If **changed**: increment version, publish to registry, anchor on-chain
4. If **unchanged**: send heartbeat only

## Chain Anchoring (APS §12)

Every new snapshot version is anchored via the registry's chain-anchor API. This creates an immutable, timestamped record of the agent's state that can be independently verified.

## Security Scanning (APS §19)

On startup and on change detection, `apsd` submits:
- Skills content → `/scan` endpoint
- System prompt → `/scan/prompt` endpoint

Scan results (score, issues, severity) are stored in snapshot metadata and exposed via the `/status` API.

## Kill Switch (APS §16)

The kill switch provides an emergency stop mechanism:
- `POST /suspend` — creates a marker file, pausing all monitoring
- `DELETE /suspend` — removes the marker, resuming operations

When suspended, the health loop skips all checks.

## API Reference

### `GET /health`
Returns daemon health status, uptime, and last scan results.

### `GET /status`
Returns full passport status including DID, version, last anchor TX, and scan score.

### `GET /passport`
Exports the current passport as an APS bundle (JSON).

### `POST /suspend`
Activates the local kill switch.

### `DELETE /suspend`
Deactivates the kill switch.

### `GET /verify`
Verifies the current passport against on-chain state.

## Deployment

```yaml
services:
  apsd:
    image: ghcr.io/cezexpl/apsd:latest
    environment:
      - APS_BOT_NAME=my-agent
      - APS_OWNER_EMAIL=owner@example.com
    volumes:
      - bot-data:/bot:ro
      - apsd-data:/data
    ports:
      - "8099:8099"
```

Required environment variables: `APS_BOT_NAME`, `APS_OWNER_EMAIL`. See the [apsd README](https://github.com/cezexpl/apsd) for full configuration.

## Compliance

An `apsd` sidecar satisfies the following APS requirements:
- §4 Identity — Ed25519 DID:key generation
- §7 Snapshots — Continuous artifact monitoring
- §12 Chain Anchoring — Immutable state records
- §16 Kill Switch — Local suspend/resume
- §19 Security Scanning — Automated prompt and skill analysis
- §21 Heartbeat — Periodic liveness signals
