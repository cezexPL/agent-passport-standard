// §21 Sybil Resistance & Reputation — APS v1.1

export interface ReputationScore {
  agentDid: string;
  score: number;
  components: {
    attestationWeight: number;
    decayFactor: number;
    rawSum: number;
  };
  computedAt: string;
}

export interface ReputationAttestation {
  weight: number;
  timestamp: string;
}

/**
 * Exponential decay: e^(-λ * ageInDays)
 * @param timestamp ISO timestamp of the attestation
 * @param lambda decay constant (default 0.01)
 */
export function computeDecay(timestamp: string, lambda: number = 0.01): number {
  const ageMs = Date.now() - new Date(timestamp).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  return Math.exp(-lambda * Math.max(0, ageDays));
}

/**
 * Reputation = Σ (weight_i * decay_i) / N
 * Normalized to [0, 1] range.
 */
export function computeReputation(agentDid: string, attestations: ReputationAttestation[], lambda?: number): ReputationScore {
  if (attestations.length === 0) {
    return {
      agentDid,
      score: 0,
      components: { attestationWeight: 0, decayFactor: 0, rawSum: 0 },
      computedAt: new Date().toISOString(),
    };
  }

  let rawSum = 0;
  let totalDecay = 0;
  for (const a of attestations) {
    const decay = computeDecay(a.timestamp, lambda);
    rawSum += a.weight * decay;
    totalDecay += decay;
  }

  const score = Math.min(1, Math.max(0, rawSum / attestations.length));

  return {
    agentDid,
    score,
    components: {
      attestationWeight: rawSum,
      decayFactor: totalDecay / attestations.length,
      rawSum,
    },
    computedAt: new Date().toISOString(),
  };
}
