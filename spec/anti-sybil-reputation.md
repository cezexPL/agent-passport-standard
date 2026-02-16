# §21 Anti-Sybil Reputation Framework

**APS v1.1 — Agent Passport Standard**
**Status:** Draft
**Created:** 2026-02-16
**Authors:** APS Working Group

## 21.1 Abstract

This section defines a sybil-resistant reputation scoring framework for APS-compliant agents. The framework computes reputation as a weighted, temporally-decaying aggregate of attestations, with safeguards against manipulation through issuer weighting, owner diversity requirements, anomaly detection, and proof-of-cost mechanisms.

## 21.2 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|-----------|
| Attestation | A signed statement about an agent's behavior or capability, issued by another entity. |
| Issuer | The entity producing an attestation. |
| Owner | The controlling principal of one or more agents. |
| Reputation Score | A normalized value in [0.0, 1.0] representing aggregate trust. |
| Snapshot | A signed, timestamped capture of an agent's reputation state. |

## 21.3 Reputation Score Formula

An agent's reputation score `R` MUST be computed as:

```
R = Σ(w_i × r_i × d_i) / Σ(w_i)
```

Where for each attestation `i`:

- `w_i` — issuer weight (see §21.4)
- `r_i` — rating value, normalized to [0.0, 1.0]
- `d_i` — temporal decay factor (see §21.5)

If `Σ(w_i) = 0` (no valid attestations), `R` MUST be reported as `null` (unrated), not `0.0`.

Implementations MUST exclude attestations that fail signature verification or anomaly detection (§21.7) before computing `R`.

### 21.3.1 Minimum Attestation Threshold

A reputation score SHOULD NOT be considered reliable with fewer than 5 attestations from at least 3 distinct issuers. Platforms MAY display such scores with a `low-confidence` qualifier.

## 21.4 Issuer Weighting

Each issuer MUST be assigned a weight `w` from the following tiers:

| Weight | Tier | Description |
|--------|------|-------------|
| 0 | `unknown` | Unverified or unrecognized issuer. Attestations MUST be excluded from score computation. |
| 1 | `self` | Self-attestation by the agent or its owner. |
| 2 | `peer` | Attestation from another APS-registered agent. |
| 3 | `verified-platform` | Platform with verified identity (e.g., domain validation, KYC). |
| 4 | `audited-platform` | Platform that has passed an independent security/governance audit. |
| 5 | `consortium` | Multi-party governance body or DAO recognized by BenchmarkGovernance.sol. |

### 21.4.1 Tier Assignment

- Tier assignment MUST be governed by on-chain registry managed through `BenchmarkGovernance.sol` (see APS §14).
- Tier upgrades REQUIRE a governance proposal with majority approval.
- Tier downgrades MAY be triggered automatically by anomaly detection (§21.7) pending governance review.
- Self-attestations (`w=1`) MUST NOT constitute more than 10% of the effective weighted score.

## 21.5 Temporal Decay

Attestation influence MUST decay over time using an exponential function:

```
d(t) = e^(-λt)
```

Where:

- `t` — time elapsed since attestation issuance, measured in days
- `λ` — decay constant, configurable per platform

### 21.5.1 Default Decay Rate

The default decay constant is:

```
λ = 0.001 per day
```

This yields approximately 50% decay over 693 days (~2 years), ensuring that reputation reflects recent behavior while preserving long-term track record.

### 21.5.2 Decay Constraints

- Platforms MUST NOT set `λ < 0.0001` (minimum ~19 years half-life) to prevent permanent reputation entrenchment.
- Platforms MUST NOT set `λ > 0.01` (maximum ~69 days half-life) to prevent excessive volatility.
- The active `λ` value MUST be published in the platform's APS configuration manifest.

### 21.5.3 Decay Floor

Attestations with `d(t) < 0.01` MAY be pruned from active computation but MUST be retained in the historical record for audit purposes.

## 21.6 Owner Diversity Requirement

To prevent sybil attacks where a single owner inflates reputation through self-controlled agents:

### 21.6.1 Single-Owner Cap

No more than **3%** of an agent's effective weighted reputation score SHALL originate from agents controlled by any single owner (excluding the agent's own owner for self-attestations, which are separately capped per §21.4.1).

```
∀ owner_k: Σ(w_i × r_i × d_i) where issuer.owner = owner_k
           ≤ 0.03 × Σ(w_i × r_i × d_i) for all i
```

Attestations exceeding this cap MUST be excluded from score computation. Implementations SHOULD process attestations in chronological order, excluding the newest when the cap is reached.

### 21.6.2 External Attestation Minimum

At least **20%** of an agent's counted attestations MUST originate from external sources — issuers whose owner is distinct from the agent's owner and from each other.

If this threshold is not met, the reputation score MUST carry an `insufficient-diversity` flag and platforms SHOULD apply a penalty multiplier of `0.5` to the computed score.

### 21.6.3 Owner Identification

Owner identity MUST be resolved via the `owner` field in the Agent Passport (APS §3). Platforms MUST maintain an owner-to-agent mapping and update it upon passport transfers.

## 21.7 Anomaly Detection Signals

Implementations MUST monitor for the following anomaly signals and flag or exclude affected attestations:

### 21.7.1 Burst Detection

- **Threshold:** More than **5 attestations per hour** from the same issuer to the same agent.
- Attestations exceeding this rate MUST be queued and rate-limited. Only the first 5 per hour SHALL be counted.
- Repeated bursts (3+ occurrences within 7 days) SHOULD trigger issuer review via governance.

### 21.7.2 Rating Uniformity

- If an issuer's last **20 or more** attestations to distinct agents all carry the maximum rating (`r_i = 1.0`), the issuer MUST be flagged as `uniform-rating-suspicious`.
- Flagged issuers' weight SHOULD be temporarily reduced by one tier (minimum `w=0`) pending review.

### 21.7.3 Timing Pattern Analysis

Implementations SHOULD detect:

- **Clock-aligned attestations** — attestations issued at exact intervals (e.g., every 3600s ± 1s), suggesting automation without genuine interaction.
- **Coordinated timing** — multiple issuers attesting to the same agent within a narrow window (<60s), suggesting orchestration.

Detected patterns MUST be logged and MAY trigger weight reduction.

### 21.7.4 Graph Analysis

Platforms SHOULD perform periodic graph analysis on the attestation network to detect:

- Reciprocal attestation rings (A→B→C→A)
- Isolated clusters with no external connections
- Sudden topology changes

Results SHOULD be reported to governance via `BenchmarkGovernance.sol` event emissions.

## 21.8 Proof-of-Cost

To prevent mass generation of fake attestations:

### 21.8.1 Cost Requirement

Each attestation SHOULD require at least one form of proof-of-cost:

| Mechanism | Description | Minimum Threshold |
|-----------|-------------|-------------------|
| **Compute** | Proof-of-work hash (e.g., SHA-256 with difficulty target) | ~1 second of computation on commodity hardware |
| **Stake** | Tokens locked for a minimum period; slashable on fraud detection | Platform-defined; RECOMMENDED ≥ 0.001 ETH equivalent |
| **Platform Fee** | Direct fee paid to the platform | Platform-defined |

### 21.8.2 Cost Verification

- The proof-of-cost MUST be included in the attestation envelope as a `costProof` field.
- Verifiers MUST validate the proof before accepting the attestation.
- Attestations without proof-of-cost MAY be accepted but SHOULD have their issuer weight reduced by one tier.

### 21.8.3 Cost Scaling

Platforms MAY implement dynamic cost scaling where the cost increases with the number of attestations issued by the same issuer within a time window (anti-spam escalation).

## 21.9 Cross-Platform Reputation Merge

When an agent migrates or is imported from another APS-compliant platform:

### 21.9.1 Initial Import Weight

Imported reputation MUST be weighted at **50%** of its original value:

```
R_imported = 0.5 × R_source
```

### 21.9.2 Progressive Trust

The import weight MUST increase linearly toward 100% as local verification accumulates:

```
weight_import(n) = min(1.0, 0.5 + 0.5 × (n / N_threshold))
```

Where:
- `n` — number of local attestations received after import
- `N_threshold` — platform-configured threshold (default: 10)

### 21.9.3 Source Verification

- The importing platform MUST verify the source platform's attestation chain signatures.
- If the source platform's issuer tier has been downgraded since export, the import weight MUST reflect the current (lower) tier.
- Cross-platform imports MUST include a signed `reputationExportCertificate` from the source platform.

### 21.9.4 Merge Conflicts

When an agent exists on multiple platforms, the merged score is:

```
R_merged = Σ(platform_weight_j × R_j) / Σ(platform_weight_j)
```

Where `platform_weight_j` follows the issuer tier of each platform.

## 21.10 Reputation Snapshot

### 21.10.1 Snapshot Structure

Platforms MUST produce periodic reputation snapshots with the following structure:

```json
{
  "version": "1.1",
  "agentDID": "did:aps:example:agent-001",
  "timestamp": "2026-02-16T01:13:00Z",
  "score": 0.847,
  "confidence": "high",
  "attestationCount": 142,
  "uniqueIssuers": 38,
  "diversityFlag": null,
  "decayLambda": 0.001,
  "anomalyFlags": [],
  "merkleRoot": "0xabc123...",
  "signature": "0xdef456..."
}
```

### 21.10.2 Snapshot Frequency

- Snapshots MUST be produced at least once every **24 hours** for agents with active attestation activity (≥1 new attestation in the period).
- Snapshots MAY be produced on-demand when triggered by governance actions.

### 21.10.3 On-Chain Anchoring

- The snapshot's `merkleRoot` and `signature` MUST be anchored on-chain via the `ReputationSnapshot` event in `BenchmarkGovernance.sol`:

```solidity
event ReputationSnapshot(
    bytes32 indexed agentId,
    uint256 timestamp,
    bytes32 merkleRoot,
    uint256 score,        // scaled to 1e18
    uint256 attestationCount,
    bytes signature
);
```

- Anchoring provides tamper evidence; the full snapshot data is stored off-chain (IPFS or platform storage) with the on-chain root serving as a verifiable commitment.

### 21.10.4 Snapshot Verification

Any party MAY verify a snapshot by:

1. Retrieving the on-chain `merkleRoot` for the given `agentId` and `timestamp`.
2. Fetching the off-chain snapshot data.
3. Recomputing the Merkle root from the attestation set.
4. Verifying the `signature` against the platform's known signing key.

## 21.11 Implementation Notes

### 21.11.1 Reference Implementation

ClawBotDen implements this framework with the following platform-specific parameters:

- `λ = 0.001` (default)
- `N_threshold = 10` for cross-platform imports
- Proof-of-cost via platform fee
- Snapshots anchored to Ethereum L2

### 21.11.2 Governance Integration

All tier assignments, anomaly escalations, and parameter changes MUST flow through `BenchmarkGovernance.sol` proposal mechanism (APS §14). Emergency tier downgrades MAY be executed by a 3-of-5 multisig with mandatory governance ratification within 72 hours.

## 21.12 Security Considerations

- **Collusion Resistance:** The owner diversity requirement (§21.6) and graph analysis (§21.7.4) mitigate coordinated sybil attacks but cannot prevent collusion between genuinely independent parties. Platforms SHOULD complement on-chain mechanisms with off-chain intelligence.
- **Privacy:** Owner-to-agent mappings required for diversity checks may reveal ownership structures. Implementations SHOULD support zero-knowledge proofs of distinct ownership where feasible.
- **Decay Gaming:** Actors may attempt to time attestations to maximize decay-adjusted impact. The burst detection mechanism (§21.7.1) partially mitigates this.
- **Cost Evasion:** Proof-of-cost mechanisms must be calibrated to remain meaningful as hardware costs decrease. Dynamic cost scaling (§21.8.3) is RECOMMENDED.

## 21.13 References

- APS §3 — Agent Passport Structure
- APS §14 — Governance (`BenchmarkGovernance.sol`)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) — Key Words for RFCs
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712) — Typed Structured Data Hashing and Signing
