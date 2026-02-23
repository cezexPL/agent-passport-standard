# CLAWChain — APS Reference Anchoring Provider

**Status:** Live / Reference Implementation  
**Provider ID:** `clawchain-420420`  
**Type:** `ethereum` (Clique PoA)  
**Date:** 2026-02-23  
**Implements:** APS §4 (Anchoring), §11 (Memory Vault), §22 (Merkle Anchoring)

---

## Overview

CLAWChain is the **reference implementation** of APS on-chain anchoring — a private Ethereum Proof-of-Authority blockchain (Clique consensus) running on the ClawBotDen k3s cluster. It demonstrates that APS anchoring works end-to-end with no dependency on public testnets.

| Property | Value |
|---|---|
| Chain ID | `420420` |
| Provider ID | `clawchain-420420` |
| Consensus | Clique PoA (3 validators) |
| Block time | 5 seconds |
| EVM Fork | London |
| RPC | `http://192.168.1.150:30545` |
| WS | `ws://192.168.1.150:30546` |
| Contract | `AgentMemoryVault` |
| Contract Address | `0xB8423ACDEdf5f446A6e00860bCBadF7987cD55b8` |
| Plugin | `clawchain-memory-sync` |

---

## APS Anchor Receipt (§4)

A CLAWChain anchor receipt conforms to `AnchorReceipt` in `anchoring.schema.json`:

```json
{
  "tx_hash": "0x5149f729d0ac3dd29d65cd49dfca703e28d57159ca5ccc62d1663396cd0680f8",
  "block": 1096,
  "timestamp": "2026-02-23T17:45:56Z",
  "provider": "clawchain-420420"
}
```

This receipt anchors the SHA-256 hash of the agent's workspace snapshot to CLAWChain block 1096.

---

## Smart Contract: AgentMemoryVault

The `AgentMemoryVault` contract implements the APS §11 (Memory Vault) anchoring interface.

### Source

```
cezexPL/clawbotden.com → contracts/src/AgentMemoryVault.sol
```

### Interface

```solidity
// Save a snapshot — anchors contentHash on-chain
function saveSnapshot(
    bytes32 contentHash,  // SHA-256 of workspace archive
    string calldata ipfsCID,   // archive filename or IPFS CID
    string calldata agentId,   // e.g. "TARS-MAIN"
    string calldata version,   // e.g. "2026-02-23"
    string calldata notes      // optional notes
) external;

// Retrieve latest snapshot for an address
function getLatest(address agent) external view returns (Snapshot memory);

// Cryptographic verification
function verifySnapshot(address agent, bytes32 contentHash) external view returns (bool);

// Count snapshots
function snapshotCount(address agent) external view returns (uint256);
```

### Snapshot Struct

```solidity
struct Snapshot {
    bytes32 contentHash; // SHA-256(workspace.tar.gz)
    string ipfsCID;      // archive reference
    uint256 timestamp;   // block.timestamp
    string agentId;      // agent identifier
    string version;      // snapshot version
    string notes;        // optional
}
```

---

## Integration with APS Memory Vault (§11)

The `memory-vault.schema.json` defines a `MemoryVault` artifact. CLAWChain acts as the `anchoring` provider for the vault hash:

```json
{
  "@context": "https://agentpassport.org/v0.2/memory-vault",
  "type": "MemoryVault",
  "agent_id": "TARS-MAIN",
  "vault_hash": "0x3440e3d10ddad859b8fc70a98d8501cf6057ab77caee5b911713dfc4d329d60c",
  "encrypted_at": "2026-02-23T17:45:56Z",
  "anchoring": {
    "tx_hash": "0x5149f729d0ac3dd29d65cd49dfca703e28d57159ca5ccc62d1663396cd0680f8",
    "block": 1096,
    "timestamp": "2026-02-23T17:45:56Z",
    "provider": "clawchain-420420"
  }
}
```

---

## OpenClaw Plugin

The `clawchain-memory-sync` plugin automates Memory Vault operations for OpenClaw agents:

```bash
# Install
cd clawbotden.com/plugins/clawchain-memory-sync && bash bin/install.sh

# Snapshot workspace → CLAWChain
clawchain-snapshot

# Restore from chain
clawchain-restore

# Verify workspace integrity
clawchain-restore --verify-only
```

**Repository:** `cezexPL/clawbotden.com → plugins/clawchain-memory-sync/`  
**Zero npm dependencies.** Node.js ≥18 + foundry `cast` required.

---

## Clone Recovery Test (§11 — Memory Vault Recovery)

On 2026-02-23, the following recovery scenario was tested and passed:

| Step | Action | Result |
|---|---|---|
| 1 | Snapshot workspace (676K) to CLAWChain | TX `0xb08a337d`, block 958 ✅ |
| 2 | Delete agent workspace from disk | Confirmed gone ✅ |
| 3 | Restore from archive + verify hash | Hash match ✅ |
| 4 | `verifySnapshot()` on-chain | `true` ✅ |

Content hash preserved across save/delete/restore:
```
0x02ada294a641a3b47216772546f4e23b299e7e3a34c54c55d97f340b63673578
```

---

## Infrastructure

CLAWChain runs on a k3s cluster (5 nodes) as 3 Kubernetes StatefulSets:

```
geth-validator-0  (mining + HTTP/WS RPC)  NodePort 30545/30546
geth-validator-1  (mining)
geth-validator-2  (mining)
```

- **Image:** `ethereum/client-go:v1.13.15` (last version with Clique PoA support)
- **Genesis:** London fork, chainId 420420, no Shanghai (Clique incompatibility)
- **Startup pattern:** `sleep 30 → miner.start()` — prevents fork-before-peer-connection race
- **Peer discovery:** ClusterIP services with hardcoded enodes in `config.toml`

**K8s manifests:** `cezexPL/clawbotden.com → blockchain/k8s/`

---

## Provider Registration

To register `clawchain-420420` as a named provider in your APS implementation:

```json
{
  "name": "clawchain-420420",
  "chain_id": 420420,
  "type": "ethereum",
  "description": "CLAWChain — private Clique PoA, APS reference implementation",
  "rpc": "http://192.168.1.150:30545",
  "contract": "0xB8423ACDEdf5f446A6e00860bCBadF7987cD55b8"
}
```

---

## References

- [`cezexPL/clawbotden.com`](https://github.com/cezexPL/clawbotden.com) — CLAWChain + AgentMemoryVault + plugin
- [`blockchain/README.md`](https://github.com/cezexPL/clawbotden.com/blob/main/blockchain/README.md) — full setup docs
- [`plugins/clawchain-memory-sync/README.md`](https://github.com/cezexPL/clawbotden.com/blob/main/plugins/clawchain-memory-sync/README.md) — OpenClaw plugin
- APS §4 — Anchoring interface specification
- APS §11 — Memory Vault schema
- APS §22 — Merkle anchoring
