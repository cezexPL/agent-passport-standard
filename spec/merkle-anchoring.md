# §22 Merkle Proofs & On-Chain Anchoring

**Status:** Normative  
**Version:** 1.1.0  
**Authors:** Cezary Grotowski  

## 22.1 Abstract

This section formalizes the Merkle tree construction, batch anchoring protocol, and multi-chain verification procedures for the Agent Passport Standard. Anchoring provides tamper-evident, timestamped proof-of-existence for agent work receipts, passport snapshots, and attestations.

## 22.2 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

| Term | Definition |
|------|-----------|
| **Anchor** | A transaction on a blockchain that commits a Merkle root hash. |
| **Batch** | A set of items (receipts, snapshots, attestations) grouped for a single anchor. |
| **Leaf** | A hash of an individual item in the batch. |
| **Merkle Root** | The top hash of a binary Merkle tree constructed from batch leaves. |
| **Merkle Proof** | The set of sibling hashes required to recompute the root from a leaf. |
| **Anchoring Receipt** | A signed document proving a Merkle root was anchored on-chain. |

## 22.3 Merkle Tree Construction

### 22.3.1 Hash Function

Implementations MUST use **Keccak-256** (as used by Ethereum) for all Merkle tree computations.

### 22.3.2 Domain Separation

To prevent second-preimage attacks, implementations SHOULD apply domain separation prefixes:

- **Leaf node:** `H(0x00 || data)`
- **Internal node:** `H(0x01 || left || right)`

where `H` is Keccak-256, `||` denotes concatenation, and `0x00`/`0x01` are single-byte prefixes.

> **Backward Compatibility (v1.0.x):** Implementations MUST accept proofs constructed without domain separation (plain `H(data)` for leaves and `H(left || right)` for internal nodes) to maintain compatibility with v1.0.x producers. Implementations SHOULD produce domain-separated proofs in v1.1+.

### 22.3.3 Leaf Ordering

Before tree construction, leaves MUST be sorted lexicographically by their hex-encoded hash values. This ensures deterministic tree construction regardless of insertion order.

```
leaves = sort([keccak256(0x00 || item_bytes) for item in batch])
```

### 22.3.4 Pair Sorting

For internal nodes, the two child hashes MUST be sorted before hashing:

```
if left > right:
    left, right = right, left
internal = keccak256(0x01 || left || right)
```

### 22.3.5 Odd Leaves

If the number of leaves at any level is odd, the last leaf MUST be duplicated to form a complete pair.

### 22.3.6 Empty Tree

A tree with zero leaves has root `0x0000000000000000000000000000000000000000000000000000000000000000` (32 zero bytes). A tree with one leaf has root equal to that leaf's hash.

### 22.3.7 Construction Algorithm

```
function buildMerkleTree(items: bytes[]) -> bytes32:
    if len(items) == 0:
        return ZERO_HASH
    
    // Step 1: Hash leaves with domain separation
    leaves = []
    for item in items:
        leaves.append(keccak256(0x00 || item))
    
    // Step 2: Sort leaves
    sort(leaves)
    
    // Step 3: Build tree bottom-up
    level = leaves
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else level[i]
            // Sort pair
            if left > right:
                left, right = right, left
            next_level.append(keccak256(0x01 || left || right))
        level = next_level
    
    return level[0]
```

## 22.4 Batch Anchoring Protocol

### 22.4.1 Batch Formation

A platform SHOULD batch items for anchoring to amortize gas costs:

1. Collect items (work receipts, snapshots, attestations) over a configurable period
2. Minimum batch size: **1** (single-item batches are valid)
3. Maximum batch size: **RECOMMENDED 1024** items
4. Maximum batch interval: platform-configurable, **RECOMMENDED 1 hour**
5. Items MUST be serialized using JCS (JSON Canonicalization Scheme, RFC 8785) before hashing

### 22.4.2 Anchoring Flow

```
1. Platform collects N items during batch window
2. Platform serializes each item to canonical JSON (JCS)
3. Platform computes Merkle tree → root_hash
4. Platform submits anchor transaction:
   anchorBatch(batch_id, root_hash, item_count)
5. Platform waits for transaction confirmation (≥1 block)
6. Platform creates AnchoringReceipt with tx details
7. Platform distributes Merkle proofs to item owners
```

### 22.4.3 Anchor Transaction

The on-chain anchor MUST include at minimum:
- `batch_id`: unique identifier (UUID or incrementing counter)
- `merkle_root`: 32-byte Keccak-256 root hash
- `item_count`: number of items in the batch

RECOMMENDED additional fields:
- `anchor_timestamp`: block timestamp of anchor
- `schema_version`: APS version used (e.g., "1.1.0")

### 22.4.4 Smart Contract Interface

```solidity
interface IAnchoringRegistry {
    event BatchAnchored(
        bytes32 indexed batchId,
        bytes32 merkleRoot,
        uint256 itemCount,
        uint256 timestamp
    );

    function anchorBatch(
        bytes32 batchId,
        bytes32 merkleRoot,
        uint256 itemCount
    ) external;

    function verifyAnchor(
        bytes32 batchId
    ) external view returns (
        bytes32 merkleRoot,
        uint256 itemCount,
        uint256 timestamp,
        address anchorer
    );
}
```

## 22.5 Anchoring Receipt

After successful on-chain anchoring, the platform MUST produce an `AnchoringReceipt`:

```json
{
  "type": "AnchoringReceipt",
  "spec_version": "1.1.0",
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "merkle_root": "0x4a5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
  "chain": {
    "chain_id": 8453,
    "chain_name": "Base",
    "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
    "tx_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "block_number": 12345678,
    "block_timestamp": "2026-02-16T02:00:00Z"
  },
  "item_count": 42,
  "created": "2026-02-16T02:00:05Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-16T02:00:05Z",
    "verificationMethod": "did:web:clawbotden.com#anchor-key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "a1b2c3d4..."
  }
}
```

## 22.6 Merkle Proof Format

A Merkle proof for an individual item MUST include:

```json
{
  "type": "MerkleProof",
  "item_hash": "0x1234...",
  "merkle_root": "0x4a5c...",
  "proof_path": [
    {"position": "left", "hash": "0xaaaa..."},
    {"position": "right", "hash": "0xbbbb..."},
    {"position": "left", "hash": "0xcccc..."}
  ],
  "leaf_index": 7,
  "tree_size": 42,
  "domain_separated": true,
  "anchoring_receipt_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 22.6.1 Proof Verification Algorithm

```
function verifyMerkleProof(proof: MerkleProof) -> bool:
    current = proof.item_hash
    
    for step in proof.proof_path:
        if proof.domain_separated:
            if step.position == "left":
                left, right = step.hash, current
            else:
                left, right = current, step.hash
            // Sort pair for determinism
            if left > right:
                left, right = right, left
            current = keccak256(0x01 || left || right)
        else:
            // v1.0.x backward compat (no domain separation)
            if step.position == "left":
                current = keccak256(step.hash || current)
            else:
                current = keccak256(current || step.hash)
    
    return current == proof.merkle_root
```

## 22.7 Multi-Chain Support

### 22.7.1 Supported Chains

APS anchoring is chain-agnostic. The following chains are RECOMMENDED:

| Chain | Chain ID | Type | Cost (approx.) | Finality | Use Case |
|-------|----------|------|-----------------|----------|----------|
| **Ethereum L1** | 1 | L1 | ~$5-50/tx | ~15 min | High-value, permanent anchors |
| **Base** | 8453 | L2 (OP Stack) | ~$0.01-0.10/tx | ~2 sec | **RECOMMENDED default** |
| **Arbitrum One** | 42161 | L2 (Rollup) | ~$0.01-0.10/tx | ~1 sec | Alternative L2 |
| **Polygon PoS** | 137 | Sidechain | ~$0.001/tx | ~2 sec | Low-cost, high-volume |
| **Solana** | — | L1 | ~$0.001/tx | ~0.4 sec | Non-EVM alternative |
| **Sui** | — | L1 | ~$0.001/tx | ~0.5 sec | Non-EVM alternative |

### 22.7.2 Chain Selection

Platforms SHOULD select anchoring chain based on:
- **Value of anchored data**: High-value → L1 or security-inheriting L2
- **Volume**: High-volume → L2 or sidechain
- **Ecosystem alignment**: EVM chains preferred for APS smart contract reuse
- **Finality requirements**: Time-sensitive → faster finality chains

### 22.7.3 Multi-Chain Anchoring

Platforms MAY anchor the same batch on multiple chains for redundancy:

```json
{
  "type": "AnchoringReceipt",
  "batch_id": "...",
  "merkle_root": "...",
  "chains": [
    {"chain_id": 8453, "tx_hash": "0x...", "block_number": 123},
    {"chain_id": 1, "tx_hash": "0x...", "block_number": 456}
  ]
}
```

## 22.8 Proof-of-Existence

Given an item and its Merkle proof, a verifier can prove the item existed at a specific time:

### 22.8.1 Verification Steps

1. **Hash the item**: Serialize to JCS, compute `item_hash = keccak256(0x00 || jcs_bytes)`
2. **Verify Merkle proof**: Walk the proof path to recompute the root (§22.6.1)
3. **Verify on-chain anchor**: Query the contract at `chain.contract_address` for `batch_id` — confirm `merkle_root` matches
4. **Extract timestamp**: The `block_timestamp` from the anchoring transaction proves existence at that time
5. **Verify platform signature**: Validate `AnchoringReceipt.proof` against the platform's public key

### 22.8.2 Cross-Chain Verification

To verify an anchor from Chain A while operating on Chain B:

1. Obtain the `AnchoringReceipt` from the anchoring platform
2. Use a block explorer API or light client to verify `tx_hash` on Chain A
3. Extract `merkle_root` from the transaction calldata or event log
4. Compare with the `merkle_root` in the receipt

Platforms SHOULD provide a REST endpoint for cross-chain verification:

```
GET /api/v1/anchoring/verify?batch_id=<id>&item_hash=<hash>
Response: { verified: true, chain: {...}, proof: {...}, timestamp: "..." }
```

## 22.9 Cost Optimization

### 22.9.1 Batch Size Trade-offs

| Batch Size | Gas Overhead | Proof Size | Latency | Recommendation |
|------------|-------------|------------|---------|----------------|
| 1 | Highest | 0 hashes | Immediate | Only for critical items |
| 16 | High | 4 hashes | Minutes | Low-volume platforms |
| 256 | Medium | 8 hashes | ~30 min | **Balanced default** |
| 1024 | Lowest | 10 hashes | ~1 hour | High-volume platforms |

### 22.9.2 Anchoring Frequency

Platforms SHOULD configure anchoring based on volume:

- **<100 items/day**: Anchor every 4 hours or on 16-item batch
- **100-1000 items/day**: Anchor every hour or on 256-item batch
- **>1000 items/day**: Anchor every 15 minutes or on 1024-item batch

### 22.9.3 L2 vs L1

For routine anchoring, implementations SHOULD use **Base L2** (chain_id: 8453). For annual or high-value snapshots (e.g., governance outcomes, founding cohort records), implementations SHOULD additionally anchor on **Ethereum L1**.

## 22.10 Arweave Integration

For permanent, immutable storage of full passport data alongside on-chain Merkle roots:

### 22.10.1 Storage Flow

1. Serialize the full batch (all items) as a JSON array
2. Upload to Arweave with tags:
   - `App-Name`: `APS`
   - `APS-Version`: `1.1.0`
   - `Batch-Id`: `<batch_id>`
   - `Merkle-Root`: `<hex_root>`
3. Record the Arweave transaction ID in the `AnchoringReceipt`:

```json
{
  "permanent_storage": {
    "provider": "arweave",
    "tx_id": "abc123...",
    "url": "https://arweave.net/abc123..."
  }
}
```

### 22.10.2 Arweave Verification

1. Fetch the batch data from `arweave.net/<tx_id>`
2. Recompute Merkle tree from the fetched items
3. Verify computed root matches on-chain anchor
4. This proves the full batch data is intact and was committed at anchor time

## 22.11 Security Considerations

### 22.11.1 Merkle Tree Attacks

- **Second-preimage attack**: Mitigated by domain separation (§22.3.2)
- **Leaf/node confusion**: Mitigated by `0x00`/`0x01` prefixes
- **Non-determinism**: Mitigated by sorted leaves and sorted pairs

### 22.11.2 Chain Reorganization

- On L1, wait for 12+ confirmations before considering an anchor final
- On L2 (Base/Arbitrum), finality is inherited from L1 after the L2 batch is posted
- Implementations SHOULD NOT treat an anchor as final until `finality_status: "finalized"`

### 22.11.3 Anchorer Trust

The anchoring platform signs the `AnchoringReceipt`. Verifiers MUST check the platform's DID and trust tier before accepting an anchor. An anchor from a `trust_tier: 0` platform provides weaker guarantees than one from `trust_tier: 4`.

### 22.11.4 Cost Attacks

An attacker could force excessive anchoring by submitting many items. Platforms SHOULD:
- Rate-limit item submission per agent
- Require proof-of-cost (§21.8) before accepting items for anchoring
- Cap batch frequency per agent

## 22.12 References

- APS §3 Security Envelope
- APS §4 On-Chain Anchoring (v1.0 base)
- APS §21 Anti-Sybil Reputation Framework (proof-of-cost)
- [EIP-155](https://eips.ethereum.org/EIPS/eip-155) — Chain ID specification
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) — JSON Canonicalization Scheme
- [Arweave Documentation](https://docs.arweave.org/)
- AgentIdentityRegistry.sol (ClawBotDen reference implementation)
