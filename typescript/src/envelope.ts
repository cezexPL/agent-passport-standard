import type { SecurityEnvelopeData, EnvelopeConfig } from './types.js';
import { canonicalizeJson, ed25519Sign, ed25519Verify, hashExcludingFields } from './crypto.js';

export class SecurityEnvelope {
  data: SecurityEnvelopeData;

  private constructor(data: SecurityEnvelopeData) {
    this.data = data;
  }

  static create(cfg: EnvelopeConfig): SecurityEnvelope {
    if (!cfg.agentDID) throw new Error('agent_did is required');

    const data: SecurityEnvelopeData = {
      '@context': 'https://agentpassport.org/v0.1',
      spec_version: '0.1.0',
      type: 'SecurityEnvelope',
      agent_did: cfg.agentDID,
      agent_snapshot_hash: cfg.agentSnapshotHash,
      capabilities: cfg.capabilities,
      sandbox: cfg.sandbox,
      memory: cfg.memory,
      trust: cfg.trust,
      envelope_hash: '',
    };

    const env = new SecurityEnvelope(data);
    data.envelope_hash = env.hash();
    return env;
  }

  static fromJson(json: string): SecurityEnvelope {
    return new SecurityEnvelope(JSON.parse(json) as SecurityEnvelopeData);
  }

  toJson(): string {
    return canonicalizeJson(this.data);
  }

  hash(): string {
    return hashExcludingFields(this.data, 'proof');
  }

  validate(): void {
    if (!this.data.agent_did) throw new Error('agent_did is required');

    const tier = this.data.trust.tier;
    if (tier < 0 || tier > 3) throw new Error(`trust tier must be 0-3, got ${tier}`);

    switch (tier) {
      case 1:
        if (this.data.trust.attestation_count < 1)
          throw new Error(`tier 1 requires >= 1 attestation, got ${this.data.trust.attestation_count}`);
        break;
      case 2:
        if (this.data.trust.attestation_count < 3)
          throw new Error(`tier 2 requires >= 3 attestations, got ${this.data.trust.attestation_count}`);
        if (this.data.trust.benchmark_coverage < 0.8)
          throw new Error(`tier 2 requires >= 0.8 benchmark coverage, got ${this.data.trust.benchmark_coverage}`);
        break;
      case 3:
        if (this.data.trust.attestation_count < 10)
          throw new Error(`tier 3 requires >= 10 attestations, got ${this.data.trust.attestation_count}`);
        if (this.data.trust.benchmark_coverage < 0.95)
          throw new Error(`tier 3 requires >= 0.95 benchmark coverage, got ${this.data.trust.benchmark_coverage}`);
        break;
    }

    const validRuntimes = new Set(['gvisor', 'firecracker', 'wasm', 'none']);
    if (!validRuntimes.has(this.data.sandbox.runtime))
      throw new Error(`invalid runtime: ${this.data.sandbox.runtime}`);

    const validPolicies = new Set(['deny-all', 'allow-list', 'unrestricted']);
    if (!validPolicies.has(this.data.sandbox.network.policy))
      throw new Error(`invalid network policy: ${this.data.sandbox.network.policy}`);
  }

  async sign(privateKey: Uint8Array): Promise<void> {
    this.data.envelope_hash = this.hash();

    const savedProof = this.data.proof;
    this.data.proof = null;

    try {
      const canonical = canonicalizeJson(this.data);
      const sig = await ed25519Sign(privateKey, new TextEncoder().encode(canonical));
      const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

      this.data.proof = {
        type: 'Ed25519Signature2020',
        created: now,
        verification_method: this.data.agent_did + '#key-1',
        proof_purpose: 'assertionMethod',
        proof_value: sig,
      };
    } catch (e) {
      this.data.proof = savedProof;
      throw e;
    }
  }
}
