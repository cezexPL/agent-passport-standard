# Kubernetes Rollout Plan — APS Control Plane + Hive Mind

This rollout targets the existing ClawBotDen k3s environment and reuses currently running blockchain services.

## Current validated cluster state (2026-02-28)

- k3s cluster reachable via kubeconfig (`/home/rancher/.kube/clawbotden.yaml`)
- Nodes ready: `w01`, `w02`, `w03`, `beta`, `gamma`
- Namespace `clawbotden` already contains:
  - `aps-portal` (Web UI)
  - `chain-anchor`
  - `profile-registry`
  - `geth-validator-0/1/2` + `geth-rpc`

## Product target

Deliver a very simple user workflow:
1. Register in panel
2. Add OpenClaw agent by one command or pairing code/QR
3. Automatic periodic sync of encrypted memory/skills
4. View and edit files in panel
5. Push edits back to agents through sync intents
6. Optional Hive Mind group sync between chosen agents

## Reference architecture on k3s

- **aps-portal**: user dashboard and pairing UI
- **control-plane-api** (new): pairing, sync intents, activity, hive groups/invites
- **agent-connector** (OpenClaw plugin/MCP): pull/push sync protocol
- **chain-anchor**: anchoring adapter (existing)
- **geth-rpc + validators**: private chain (existing)
- **object storage**: encrypted vault blobs (MinIO target)
- **profile-registry/reputation services**: trust and history views

## Security model

- Agent identity: DID + signed challenge-response pairing
- Private data: encrypted client-side (AES-256-GCM), stored as blobs
- On-chain: hashes, membership events, receipts; no raw memories/skills
- Public by default: reputation/work history metadata only
- Group sharing: explicit opt-in with invite token + acceptance

## Phase rollout

### Phase 1 — Control plane MVP in-cluster
- Deploy `control-plane-api`
- Integrate with existing `aps-portal`
- Implement `sync-intent` queue + retries
- Add OpenClaw bootstrap command/plugin

### Phase 2 — Encrypted vault + file operations
- MinIO bucket for encrypted payloads
- File versioning and restore paths
- UI file explorer + editor + push-to-agent

### Phase 3 — Hive Mind groups
- Group create/invite/accept/revoke
- Scoped sharing (`memories`, `skills`, `project-notes`)
- Group key rotation on membership change

### Phase 4 — Reputation and collaboration views
- Project/work history timeline
- Collaboration graph for agent teams
- Portable summaries via APS bundle imports

## Ops requirements

- Backup schedule for object storage and chain state
- Alerting for sync backlog and failed intents
- SLOs:
  - Pairing completion < 3 minutes (p50)
  - Sync success > 95%
  - Intent completion > 98%

## Suggested first implementation tasks

1. Add `control-plane-api` deployment + service in `clawbotden`
2. Add `sync-intent` and `hive-*` schema validation in gateway layer
3. Extend `aps-portal` with Agents table: status, last sync, actions
4. Ship OpenClaw bootstrap command (`aps connect --panel <url>`)
