# §22 Merkle Proofs & Advanced On-Chain Anchoring

**APS v1.1 Extension**  
**Status:** Draft  
**Date:** 2026-02-16  
**Author:** Cezary Grotowski <c.grotowski@gmail.com>  
**Extends:** §4 (Anchoring Providers), §6.3 (Merkle Trees), §14 (Trust Levels)

---

## 22.1 Introduction

This section formalizes the Merkle tree construction algorithm, defines a
multi-chain batch anchoring protocol, and specifies cross-chain verification
procedures for the Agent Passport Standard. It supersedes the informational
guidance in §6.3 and elevates domain-separated Merkle trees from RECOMMENDED
to REQUIRED for all new implementations (v1.1+).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119].

---

## 22.2 Merkle Tree Construction

### 22.2.1 Domain Separation

All v1.1 implementations MUST use domain-separated hashing to prevent
second-preimage attacks between leaf and internal nodes.

```
LEAF_PREFIX  = 0x00   (1 byte)
NODE_PREFIX  = 0x01   (1 byte)
```

### 22.2.2 Hash Functions

The hash function H is Keccak-256 as specified in [FIPS 202] (NOT SHA-3;
Keccak-256 uses different padding). All hash values are 32 bytes.

### 22.2.3 Leaf Computation

Given a receipt hash `r` (32 bytes, the Keccak-256 of the JCS-canonicalized
receipt):

```
leaf = H(0x00 || r)
```

Where `||` denotes byte concatenation.

**Example:**

```
r    = 0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
leaf = keccak256(0x00a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2)
     = 0x7f3e8a...  (32 bytes)
```

### 22.2.4 Internal Node Computation

Given two child hashes `a` and `b` (each 32 bytes):

```
node = H(0x01 || min(a, b) || max(a, b))
```

Where `min` and `max` are lexicographic comparison of the 32-byte values.
Sorted-pair concatenation ensures that the tree is order-independent: the same
set of leaves always produces the same root regardless of insertion order.

**Example:**

```
a    = 0x1111111111111111111111111111111111111111111111111111111111111111
b    = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
node = keccak256(0x01 || a || b)   // a < b lexicographically
     = keccak256(0x011111...1111aaaa...aaaa)
```

### 22.2.5 Tree Construction Algorithm

```
function buildMerkleTree(receipt_hashes: bytes32[]) -> bytes32:
    REQUIRE len(receipt_hashes) >= 1

    // Step 1: Compute leaves with domain separation
    leaves = [H(0x00 || r) for r in receipt_hashes]

    // Step 2: Sort leaves lexicographically
    sort(leaves)

    // Step 3: Iteratively combine pairs
    level = leaves
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                a = level[i]
                b = level[i + 1]
                next_level.append(H(0x01 || min(a, b) || max(a, b)))
            else:
                // Odd element: promote to next level unchanged
                next_level.append(level[i])
        level = next_level

    return level[0]  // Merkle root
```

**Properties:**
- Deterministic: same set of receipt hashes → same root.
- Proof size: O(log₂ N) hashes for N leaves.
- Domain separation prevents leaf/node confusion attacks per [RFC 6962 §2.1].

### 22.2.6 Proof Generation

A Merkle proof for receipt hash `r` consists of an ordered array of
`(sibling_hash, position)` pairs from leaf to root:

```json
{
  "receipt_hash": "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "leaf_index": 3,
  "proof": [
    { "hash": "0x4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f", "position": "left" },
    { "hash": "0x8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c", "position": "right" },
    { "hash": "0xf1e2d3c4b5a69788796a5b4c3d2e1f0fabcdef0123456789abcdef0123456789ab", "position": "left" }
  ],
  "root": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```

### 22.2.7 Proof Verification Algorithm

```
function verifyProof(receipt_hash, proof, root) -> bool:
    current = H(0x00 || receipt_hash)
    for step in proof:
        sibling = step.hash
        current = H(0x01 || min(current, sibling) || max(current, sibling))
    return current == root
```

Implementations MUST reject proofs where any hash is not exactly 32 bytes.

---

## 22.3 Batch Anchoring Protocol

### 22.3.1 Overview

Rather than anchoring each receipt individually (expensive), implementations
SHOULD batch multiple receipts into a single Merkle tree and anchor only the
root hash on-chain.

### 22.3.2 Protocol Steps

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│ 1. Collect   │────▶│ 2. Build     │────▶│ 3. Anchor     │────▶│ 4. Distribute│
│ N receipts   │     │ Merkle tree  │     │ root on-chain │     │ proofs       │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
```

**Step 1 — Collection:**
The anchoring service collects work receipts and passport snapshots during a
batching window. Each item is JCS-canonicalized and hashed with Keccak-256.

**Step 2 — Tree Construction:**
Apply the algorithm in §22.2.5 to produce the batch Merkle root.

**Step 3 — On-Chain Anchoring:**
Submit `anchorBatchRoot(bytes32 root, uint256 batchSize)` to the
AgentIdentityRegistry contract (see §22.4.4).

**Step 4 — Proof Distribution:**
For each receipt in the batch, generate the Merkle proof (§22.2.6) and package
it with the AnchoringReceipt (§22.4) for the holder to store.

### 22.3.3 Batching Window

Implementations MUST define a batching policy. RECOMMENDED defaults:

| Parameter             | Value       | Rationale                          |
|-----------------------|-------------|------------------------------------|
| `max_batch_size`      | 1024        | Proof depth ≤ 10 hashes           |
| `min_batch_size`      | 1           | Don't delay single urgent anchors  |
| `max_wait_seconds`    | 3600        | Anchor at least hourly             |
| `trigger_threshold`   | 256         | Anchor when queue reaches 256      |

The batch window closes when ANY trigger condition is met.

---

## 22.4 Anchoring Receipt

### 22.4.1 Schema

An AnchoringReceipt binds a batch Merkle root to a specific on-chain
transaction across any supported chain.

```json
{
  "type": "AnchoringReceipt",
  "version": "1.1",
  "batch_root": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "batch_size": 256,
  "chain_id": "eip155:8453",
  "tx_hash": "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "block_number": 28451033,
  "timestamp": "2026-02-16T01:30:00Z",
  "contract_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
  "anchor_method": "anchorBatchRoot(bytes32,uint256)"
}
```

### 22.4.2 Required Fields

| Field              | Type    | Description                                              |
|--------------------|---------|----------------------------------------------------------|
| `type`             | string  | MUST be `"AnchoringReceipt"`.                            |
| `version`          | string  | MUST be `"1.1"`.                                         |
| `batch_root`       | Hex256  | Keccak-256 Merkle root of the batch.                     |
| `batch_size`       | integer | Number of leaves in the batch. MUST be ≥ 1.              |
| `chain_id`         | string  | CAIP-2 chain identifier (see §22.5).                     |
| `tx_hash`          | string  | Transaction hash on the target chain.                    |
| `block_number`     | integer | Block number containing the transaction. 0 if N/A.       |
| `timestamp`        | string  | ISO 8601 UTC timestamp of the block.                     |
| `contract_address` | string  | Address of the anchoring contract.                       |

### 22.4.3 Optional Fields

| Field              | Type    | Description                                              |
|--------------------|---------|----------------------------------------------------------|
| `anchor_method`    | string  | Contract method signature used.                          |
| `gas_used`         | integer | Gas consumed by the transaction.                         |
| `anchored_by`      | DID     | DID of the anchoring service operator.                   |
| `co_anchors`       | array   | Additional chain anchors for the same batch root.        |

### 22.4.4 Smart Contract Interface

The `AgentIdentityRegistry` contract (or compatible) MUST implement:

```solidity
interface IAnchorRegistry {
    event BatchAnchored(
        bytes32 indexed batchRoot,
        uint256 batchSize,
        address indexed anchorer,
        uint256 timestamp
    );

    /// @notice Anchor a Merkle root for a batch of receipts.
    /// @param batchRoot The Merkle root of the receipt batch.
    /// @param batchSize Number of receipts in the batch.
    function anchorBatchRoot(bytes32 batchRoot, uint256 batchSize) external;

    /// @notice Verify whether a batch root has been anchored.
    /// @param batchRoot The Merkle root to verify.
    /// @return anchored True if the root exists.
    /// @return timestamp Block timestamp when anchored.
    /// @return anchorer Address that submitted the root.
    function verifyBatchRoot(bytes32 batchRoot)
        external
        view
        returns (bool anchored, uint256 timestamp, address anchorer);
}
```

Storage pattern:

```solidity
struct AnchorRecord {
    uint256 timestamp;
    uint256 batchSize;
    address anchorer;
}

mapping(bytes32 => AnchorRecord) public anchors;
```

---

## 22.5 Multi-Chain Support

### 22.5.1 Chain Identifier Format

All chain references MUST use [CAIP-2] identifiers:

| Chain           | CAIP-2 Identifier     | Type         | Notes                          |
|-----------------|-----------------------|--------------|--------------------------------|
| Ethereum L1     | `eip155:1`            | EVM          | Highest finality, highest cost |
| Base L2         | `eip155:8453`         | EVM (OP)     | RECOMMENDED default            |
| Arbitrum One    | `eip155:42161`        | EVM (Nitro)  | Low cost, fast finality        |
| Polygon PoS     | `eip155:137`          | EVM          | Low cost                       |
| Sui             | `sui:mainnet`         | Move         | Object-based anchoring         |
| Solana          | `solana:mainnet`      | SVM          | Program-based anchoring        |

### 22.5.2 EVM Chains (Ethereum, Base, Arbitrum, Polygon)

EVM chains share the same contract interface (§22.4.4). Implementations MUST
deploy the same `IAnchorRegistry` interface on each supported chain.

**Transaction encoding:**

```
anchorBatchRoot(bytes32,uint256)
selector: keccak256("anchorBatchRoot(bytes32,uint256)")[:4]
data:    selector || batchRoot (32 bytes) || batchSize (uint256, 32 bytes)
```

### 22.5.3 Sui

On Sui, the anchoring module uses a shared object:

```move
module aps::anchor_registry {
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};

    struct AnchorRegistry has key {
        id: UID,
        anchors: Table<vector<u8>, AnchorRecord>,
    }

    struct AnchorRecord has store {
        timestamp: u64,
        batch_size: u64,
        anchorer: address,
    }

    public entry fun anchor_batch_root(
        registry: &mut AnchorRegistry,
        batch_root: vector<u8>,
        batch_size: u64,
        ctx: &mut TxContext,
    ) { /* ... */ }
}
```

The `chain_id` in the AnchoringReceipt MUST be `"sui:mainnet"` (or
`"sui:testnet"`). The `tx_hash` is the Sui transaction digest (base58).
The `contract_address` is the Sui object ID of the `AnchorRegistry`.

### 22.5.4 Solana

On Solana, the anchoring program stores records in a PDA:

```rust
// Program instruction: AnchorBatchRoot { batch_root: [u8; 32], batch_size: u64 }
// PDA seed: ["anchor", batch_root]
```

The `chain_id` MUST be `"solana:mainnet"` (or `"solana:devnet"`). The
`tx_hash` is the Solana transaction signature (base58). The
`contract_address` is the program ID.

### 22.5.5 Chain-Agnostic Verification

Verifiers MUST support resolving any CAIP-2 chain identifier. The verification
algorithm is:

```
function verifyAnchoringReceipt(receipt: AnchoringReceipt) -> bool:
    chain = resolveChain(receipt.chain_id)
    provider = getProvider(chain)

    // Verify on-chain
    (anchored, timestamp, anchorer) = provider.verifyBatchRoot(
        receipt.batch_root,
        receipt.contract_address
    )

    REQUIRE anchored == true
    REQUIRE abs(timestamp - parse(receipt.timestamp)) < 60  // 60s tolerance
    return true
```

---

## 22.6 Proof-of-Existence

### 22.6.1 Definition

A Proof-of-Existence (PoE) demonstrates that a specific receipt existed at or
before time T. It consists of three components:

1. **Receipt hash** — `keccak256(JCS(receipt))`
2. **Merkle proof** — path from leaf to batch root (§22.2.6)
3. **Anchoring receipt** — binding the batch root to a blockchain timestamp (§22.4)

### 22.6.2 Composite Proof Structure

```json
{
  "type": "ProofOfExistence",
  "version": "1.1",
  "receipt_hash": "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "receipt_type": "WorkReceipt",
  "merkle_proof": {
    "leaf_index": 42,
    "proof": [
      { "hash": "0x4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f", "position": "left" },
      { "hash": "0x8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c", "position": "right" },
      { "hash": "0xf1e2d3c4b5a69788796a5b4c3d2e1f0fabcdef0123456789abcdef0123456789ab", "position": "left" }
    ],
    "root": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  },
  "anchoring_receipt": {
    "type": "AnchoringReceipt",
    "version": "1.1",
    "batch_root": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "batch_size": 256,
    "chain_id": "eip155:8453",
    "tx_hash": "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "block_number": 28451033,
    "timestamp": "2026-02-16T01:30:00Z",
    "contract_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
  },
  "existence_time": "2026-02-16T01:30:00Z"
}
```

### 22.6.3 Verification Algorithm

```
function verifyProofOfExistence(poe: ProofOfExistence) -> (bool, timestamp):
    // Step 1: Verify Merkle proof
    REQUIRE verifyProof(
        poe.receipt_hash,
        poe.merkle_proof.proof,
        poe.merkle_proof.root
    )

    // Step 2: Verify root matches anchoring receipt
    REQUIRE poe.merkle_proof.root == poe.anchoring_receipt.batch_root

    // Step 3: Verify on-chain anchoring
    REQUIRE verifyAnchoringReceipt(poe.anchoring_receipt)

    // Step 4: Return the blockchain-attested timestamp
    return (true, poe.anchoring_receipt.timestamp)
```

Verifiers MUST treat the `block_number` timestamp from the chain as the
authoritative existence time, NOT the `timestamp` field in the receipt
(which is informational).

---

## 22.7 Cross-Chain Verification

### 22.7.1 Problem Statement

An agent operating on chain B receives a ProofOfExistence anchored on chain A.
The verifier must confirm the anchoring without direct access to chain A.

### 22.7.2 Verification Strategies

Implementations MUST support at least one of the following strategies:

**Strategy 1: Direct RPC Verification (RECOMMENDED)**

The verifier queries chain A's RPC endpoint to call `verifyBatchRoot()`:

```
function crossChainVerify(poe: ProofOfExistence, rpc_endpoints: Map) -> bool:
    chain_id = poe.anchoring_receipt.chain_id
    rpc = rpc_endpoints[chain_id]
    REQUIRE rpc != null

    result = rpc.call(
        to: poe.anchoring_receipt.contract_address,
        data: encodeCall("verifyBatchRoot", poe.anchoring_receipt.batch_root)
    )
    return result.anchored == true
```

**Strategy 2: Light Client / Header Proof**

For trustless verification, include a block header proof:

```json
{
  "cross_chain_proof": {
    "strategy": "header_proof",
    "source_chain": "eip155:1",
    "block_header": "0x...",
    "state_proof": ["0x...", "0x..."],
    "storage_slot": "0x..."
  }
}
```

**Strategy 3: Bridge Relay**

Use a cross-chain messaging bridge (e.g., LayerZero, Hyperlane) to relay
the verification result. The relay message MUST include the batch root and
the source chain's block timestamp.

### 22.7.3 Trust Model

| Strategy      | Trust Assumptions                      | Latency    |
|---------------|----------------------------------------|------------|
| Direct RPC    | Trust RPC provider                     | Seconds    |
| Header Proof  | Trust chain consensus only (trustless) | Minutes    |
| Bridge Relay  | Trust bridge validators                | Minutes    |

Implementations SHOULD document which strategy they use. For Trust Level 3
(Full), at least two independent verification paths are RECOMMENDED.

---

## 22.8 Cost Optimization

### 22.8.1 Gas Estimates

Anchoring a single `bytes32` root costs approximately:

| Chain          | Gas (approx)    | Cost (USD, est.) | Finality     |
|----------------|-----------------|-------------------|--------------|
| Ethereum L1    | 45,000 gas      | $2.00 – $15.00   | ~12 min      |
| Base L2        | 45,000 L2 gas   | $0.001 – $0.01   | ~2 sec + L1  |
| Arbitrum One   | 45,000 L2 gas   | $0.001 – $0.02   | ~1 sec + L1  |
| Polygon PoS    | 45,000 gas      | $0.005 – $0.05   | ~2 sec       |
| Sui            | ~1,000 gas      | $0.001 – $0.005  | ~2 sec       |
| Solana         | ~5,000 CU       | $0.0001 – $0.001 | ~400 ms      |

### 22.8.2 Batch Size Tradeoffs

```
Cost per receipt = (anchor_tx_cost) / batch_size

Example (Base L2, $0.005/tx):
  Batch size 1:    $0.005 / receipt
  Batch size 256:  $0.00002 / receipt
  Batch size 1024: $0.000005 / receipt
```

Larger batches reduce per-receipt cost but increase latency (longer batching
windows). Implementations SHOULD target 256–1024 receipts per batch.

### 22.8.3 L2 vs L1 Strategy

RECOMMENDED tiered approach:

1. **Primary anchor:** Base L2 or Arbitrum (low cost, fast).
2. **Periodic L1 checkpoint:** Every 24 hours (or every 10,000 receipts),
   anchor a "root of roots" on Ethereum L1 for maximum security.

```json
{
  "type": "AnchoringReceipt",
  "version": "1.1",
  "batch_root": "0x...",
  "batch_size": 10000,
  "chain_id": "eip155:1",
  "tx_hash": "0x...",
  "block_number": 19500000,
  "timestamp": "2026-02-16T00:00:00Z",
  "contract_address": "0x...",
  "anchor_method": "anchorCheckpoint(bytes32,uint256,bytes32[])",
  "co_anchors": [
    {
      "chain_id": "eip155:8453",
      "tx_hash": "0x...",
      "block_number": 28451033
    }
  ]
}
```

### 22.8.4 Anchoring Frequency Guidance

| Use Case                     | Recommended Frequency | Chain         |
|------------------------------|-----------------------|---------------|
| Real-time agent work         | Every 15 minutes      | Base L2       |
| Daily passport snapshots     | Every 24 hours        | Base L2 + L1  |
| Regulatory compliance        | Every 1 hour + L1     | L2 + L1       |
| Low-cost development/testing | On-demand             | Sepolia       |

---

## 22.9 Arweave Integration

### 22.9.1 Purpose

Arweave provides permanent, immutable storage for full passport data that is
too large for on-chain anchoring (which stores only 32-byte hashes). The
combination of Merkle anchoring (compact, on-chain) with Arweave (complete
data, permanent) provides both verifiability and data availability.

### 22.9.2 What to Store on Arweave

| Data                     | Frequency       | Tags                                    |
|--------------------------|-----------------|------------------------------------------|
| Full passport snapshot   | On version bump | `APS-Type: PassportSnapshot`             |
| Batch receipt set        | Per batch       | `APS-Type: ReceiptBatch`                 |
| Merkle tree (full)       | Per batch       | `APS-Type: MerkleTree`                   |
| Anchoring receipt        | Per anchor      | `APS-Type: AnchoringReceipt`             |

### 22.9.3 Arweave Transaction Format

```json
{
  "data": "<JCS-canonicalized passport or batch JSON>",
  "tags": [
    { "name": "Content-Type", "value": "application/json" },
    { "name": "APS-Version", "value": "1.1" },
    { "name": "APS-Type", "value": "PassportSnapshot" },
    { "name": "APS-DID", "value": "did:key:z6Mkf5rGMoatrSj1f..." },
    { "name": "APS-Merkle-Root", "value": "0xdeadbeef..." },
    { "name": "APS-Chain-Anchor", "value": "eip155:8453:0x9f86d081..." }
  ]
}
```

### 22.9.4 Merkle Roots as Arweave Index

To enable efficient retrieval, each Arweave upload MUST include the
`APS-Merkle-Root` tag. This allows GraphQL queries to locate all data
associated with a particular anchoring batch:

```graphql
query {
  transactions(
    tags: [
      { name: "APS-Merkle-Root", values: ["0xdeadbeef..."] }
    ]
  ) {
    edges {
      node {
        id
        tags { name value }
      }
    }
  }
}
```

### 22.9.5 Verification with Arweave

To verify a receipt using Arweave as the data availability layer:

```
function verifyViaArweave(receipt_hash, merkle_root):
    // 1. Query Arweave for the full Merkle tree
    tree_tx = arweave.query(tag: "APS-Merkle-Root", value: merkle_root,
                            tag: "APS-Type", value: "MerkleTree")

    // 2. Download and parse the tree
    tree = JSON.parse(arweave.getData(tree_tx.id))

    // 3. Verify the receipt_hash is a leaf
    REQUIRE receipt_hash IN tree.leaves

    // 4. Reconstruct root from tree data
    computed_root = buildMerkleTree(tree.leaves)
    REQUIRE computed_root == merkle_root

    // 5. Verify the root was anchored on-chain (§22.6.3)
    // ... standard chain verification ...
```

### 22.9.6 Cost Considerations

Arweave pricing is per byte, permanently stored (~$5/MB at time of writing).
A typical passport snapshot is 2–10 KB ($0.01–$0.05). A batch of 256 receipts
with Merkle tree is approximately 50–100 KB ($0.25–$0.50).

Implementations SHOULD compress JSON data before uploading (gzip, then store
with `Content-Encoding: gzip` tag).

---

## 22.10 Backward Compatibility

### 22.10.1 v1.0 Merkle Trees

Implementations MUST accept Merkle proofs without domain separation (v1.0
format) when verifying existing proofs. New proofs MUST use domain separation.

Detection heuristic: if the proof was generated before the v1.1 effective date
(or the AnchoringReceipt version is `"1.0"`), fall back to non-domain-separated
verification.

### 22.10.2 v1.0 Anchoring Receipts

The v1.0 `AnchorReceipt` schema (from `anchoring.schema.json`) uses
`provider` instead of `chain_id`. Implementations MUST map legacy provider
strings to CAIP-2 identifiers:

| Legacy `provider`    | CAIP-2 `chain_id`  |
|----------------------|---------------------|
| `"base-sepolia"`     | `"eip155:84532"`    |
| `"base-mainnet"`     | `"eip155:8453"`     |
| `"ethereum-mainnet"` | `"eip155:1"`        |
| `"arweave-mainnet"`  | `"arweave:mainnet"` |

---

## 22.11 Security Considerations

1. **Second-preimage resistance:** Domain separation (§22.2.1) prevents an
   attacker from constructing a leaf that collides with an internal node.

2. **Batch poisoning:** Anchoring services MUST validate each receipt before
   including it in a batch. A malformed receipt in a batch does not invalidate
   other receipts (each has an independent Merkle proof).

3. **RPC trust in cross-chain verification:** Direct RPC verification (§22.7.2
   Strategy 1) trusts the RPC provider. For high-assurance scenarios, verifiers
   SHOULD use multiple independent RPC endpoints or header proofs.

4. **Timestamp accuracy:** Block timestamps on PoS chains have bounded drift
   (typically ≤ 12 seconds). Implementations MUST NOT rely on sub-minute
   timestamp precision for ordering guarantees.

5. **Arweave immutability:** Data uploaded to Arweave is permanent. Passport
   snapshots containing sensitive data MUST be encrypted before upload.
   See §9 (Memory Vault) for encryption requirements.

6. **Contract upgrade risk:** Anchoring contracts SHOULD be immutable (no
   proxy pattern) or use a timelock for upgrades. The contract address in the
   AnchoringReceipt permanently identifies the verification endpoint.

---

## 22.12 Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC 6962] Laurie, B., Langley, A., and E. Kasper, "Certificate
  Transparency", RFC 6962, June 2013.
- [RFC 8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization
  Scheme (JCS)", RFC 8785, June 2020.
- [CAIP-2] Chain Agnostic Improvement Proposal 2, "Blockchain ID Specification".
- [FIPS 202] NIST, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output
  Functions", August 2015. (Note: APS uses Keccak-256, not SHA-3-256.)
- [APS §4] Agent Passport Standard, "Anchoring Providers".
- [APS §6.3] Agent Passport Standard, "Merkle Trees".
- [APS §14] Agent Passport Standard, "Trust Levels & Blockchain Anchoring".
