# §24 Control Plane & Hive Mind Groups (Draft)

**Status:** Draft extension for APS v1.1+

This section defines a UX-first control plane for encrypted agent memory sync, Web UI management, and opt-in multi-agent knowledge sharing groups (“Hive Mind”).

## 24.1 Objectives

Implementations SHOULD provide a non-technical user flow for:

1. Agent registration/pairing in under 3 minutes
2. Periodic encrypted backup/sync of Memory Vault data
3. Web UI file browsing and controlled edits
4. Skill copy and sync orchestration between selected agents
5. Optional group knowledge-sharing with explicit bilateral consent

## 24.2 Simplicity requirements

- Users MUST NOT be required to manage wallets, gas, or raw chain transactions.
- Pairing MUST support one-time code and/or QR flow.
- A single command bootstrap SHOULD be available for OpenClaw-like agents.
- Blockchain interaction SHOULD be delegated to a relayer/service account.

## 24.3 Control Plane discovery

Platforms implementing this extension SHOULD publish additional fields in:

`GET /.well-known/agent-passport-standard`

Recommended fields:
- `control_plane_api`
- `pairing_endpoint`
- `sync_pull_endpoint`
- `sync_push_endpoint`
- `hivemind_endpoint`

## 24.4 Data confidentiality and public verifiability

### Private data (encrypted)

The following MUST remain encrypted at rest and in transit storage:
- memory files
- skill payloads and internal notes
- runtime preferences

### Public trust data

The following MAY be publicly readable/verifiable:
- Reputation Summary
- Work Receipt hashes and collaboration metadata
- Anchor receipts and timestamps

Implementations SHOULD expose trust outcomes without exposing private memory content.

## 24.5 Sync intents

Control plane operations SHOULD be represented as SyncIntent artifacts (see `sync-intent.schema.json`).

Typical operations:
- `copy-skill`
- `sync-now`
- `restore-version`

Implementations MUST track lifecycle:
- `queued` → `running` → `done` / `failed`

Implementations SHOULD support retryable failures with bounded attempts and backoff.

## 24.6 Web UI edit propagation

When a user edits a file in the Web UI:

1. Control plane writes a new encrypted version to vault storage.
2. New version hash/cid SHOULD be anchored (directly or batched).
3. A SyncIntent is queued for target agent(s).
4. Agent applies update and reports status via sync push.

All edits MUST be versioned and reversible.

## 24.7 Hive Mind Groups

A Hive Mind Group is an opt-in sharing domain with scoped synchronization.

### Group rules

- Group membership MUST require explicit owner consent.
- Invites SHOULD use two-step confirmation:
  1) inviter creates invite on control plane
  2) invitee confirms via token/challenge
- Membership changes SHOULD trigger group key rotation.

### Sharing scope

Implementations SHOULD support per-group share scopes:
- `memories`
- `skills`
- `project-notes`

Implementations SHOULD support channel/project filtering to avoid blind full-memory flooding.

## 24.8 Security model

- Agent identity MUST be bound to DID + signature proof.
- Agent impersonation MUST be prevented by challenge-response during pairing.
- Vault content MUST remain encrypted client-side (AES-256-GCM or equivalent).
- On-chain records SHOULD store pointers/hashes, not raw memory content.

## 24.9 Kubernetes reference deployment (informative)

A typical deployment includes:
- Web UI
- Control plane API
- Relayer
- Private chain RPC/validators (or equivalent provider)
- Object storage for encrypted vault blobs (e.g., MinIO)

The control plane can run on k3s with horizontal API scaling and periodic workers for sync intents.

## 24.10 Interoperability

Platforms MAY export/import Hive Mind-compatible states using existing APS Bundle + Memory Vault artifacts, plus SyncIntent logs for replay/audit.

Imported agents SHOULD start at conservative local trust defaults unless policy explicitly permits transfer of prior trust tier.
