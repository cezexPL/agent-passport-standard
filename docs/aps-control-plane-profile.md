# APS Control Plane Profile (Draft)

**Goal:** Add a practical, UX-first profile on top of Agent Passport Standard so non-technical users can:

1. Connect bots in under 3 minutes
2. Backup/sync encrypted memory and skills
3. Copy skills between bots from a Web UI
4. Preserve reputation, work history, and collaboration history across platforms

This profile reuses existing APS primitives instead of creating a parallel standard.

---

## 1) Reuse Existing APS Building Blocks

- **Identity:** Agent Passport (`agent-passport.schema.json`)
- **Encrypted backup:** Memory Vault (§11, `memory-vault.schema.json`)
- **Trust/reputation:** Reputation Summary (`reputation-summary.schema.json`)
- **Cross-platform migration:** Passport Bundle (`bundle.schema.json`)
- **Collaboration:** Work Receipt + Collaboration History (§12)
- **Anchoring provider:** private EVM chain (e.g., CLAWChain) or other provider interface (§4)

No new identity format is needed. We only add a control-plane workflow and a small sync-intent schema.

---

## 2) UX Requirements (Normative for this profile)

- User MUST NOT need to understand wallets, gas, or chain internals.
- Pairing MUST support short-lived code/QR.
- UI MUST expose:
  - connected agents
  - last sync status
  - file preview/version history
  - one-click skill copy between agents
- All operations MUST be reversible (version restore).
- Blockchain writes SHOULD be gasless for users (relayer/service account).

---

## 3) Control Plane Components

- **Web UI** (simple user panel)
- **Control Plane API** (pairing, sync intents, activity log)
- **Agent Sidecar/Connector** (pull/push protocol)
- **Vault Storage** (encrypted blobs in object storage, e.g., MinIO)
- **Anchoring Provider** (self-hosted private chain preferred)

### Data split

- **On-chain:** hash pointers, ACL events, timestamped anchors
- **Off-chain:** encrypted content blobs (`skills`, `soul`, `memories`, `agent_config`)

---

## 4) Proposed New Artifact: Sync Intent

A small artifact that expresses user actions like “copy skill from agent A to B”.

Examples:
- `copy-skill`
- `sync-now`
- `restore-version`

This artifact is transport/control-plane metadata and can optionally be included in activity/audit exports.

---

## 5) Reputation + Collaboration Continuity

When migrating agent state between platforms:

1. Import passport bundle
2. Verify signatures + optional anchoring proofs
3. Import reputation summary with local trust policy
4. Import collaboration graph signals from verified receipts only
5. Start imported agent at conservative local trust tier unless policy allows direct carry-over

---

## 6) Suggested Deployment (Self-Hosted)

- Kubernetes cluster hosts:
  - Control Plane API
  - Web UI
  - Relayer
  - optional private EVM nodes (or external self-hosted chain)
- MinIO stores encrypted vault blobs
- Agent connectors run close to bot runtimes (OpenClaw, Codex workflows, etc.)

---

## 7) Migration Plan from agent-vault-protocol repo

1. Keep `agent-vault-protocol` as incubation playground (implementation-first).
2. Move normative artifacts/spec changes into `agent-passport-standard`.
3. Reference implementation can stay in separate repos but MUST map to APS schemas.
4. Add conformance tests for:
   - encrypted vault lifecycle
   - sync intent validation
   - bundle import/export with reputation + collaboration integrity

---

## 8) Immediate Next Steps

1. Add `sync-intent.schema.json` to `/spec`
2. Add control-plane section in `spec/SPECIFICATION.md` (or as extension file)
3. Provide `.well-known` discovery fields for control-plane endpoints
4. Add minimal end-to-end example: pair -> push vault -> copy skill -> verify history
