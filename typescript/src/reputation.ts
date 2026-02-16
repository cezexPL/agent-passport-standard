import { canonicalizeJson, ed25519Sign, ed25519Verify } from './crypto.js';
import type { Proof } from './types.js';

export interface ReputationSummaryData {
  agent_did: string;
  generated_at: string;
  total_jobs: number;
  successful_jobs: number;
  failed_jobs: number;
  average_score: number;
  trust_tier: number;
  attestation_count: number;
  categories: Record<string, unknown>;
  proof?: Proof | null;
}

export class ReputationSummary {
  data: ReputationSummaryData;

  constructor(data: ReputationSummaryData) {
    this.data = data;
  }

  private toDict(includeProof = true): Record<string, unknown> {
    const d: Record<string, unknown> = {
      agent_did: this.data.agent_did,
      generated_at: this.data.generated_at,
      total_jobs: this.data.total_jobs,
      successful_jobs: this.data.successful_jobs,
      failed_jobs: this.data.failed_jobs,
      average_score: this.data.average_score,
      trust_tier: this.data.trust_tier,
      attestation_count: this.data.attestation_count,
      categories: this.data.categories,
    };
    if (includeProof && this.data.proof) {
      d.proof = this.data.proof;
    }
    return d;
  }

  async sign(privateKey: Uint8Array): Promise<void> {
    const canonical = canonicalizeJson(this.toDict(false));
    const sig = await ed25519Sign(privateKey, new TextEncoder().encode(canonical));
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    this.data.proof = {
      type: 'Ed25519Signature2020',
      created: now,
      verificationMethod: this.data.agent_did + '#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: sig,
    };
  }

  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.data.proof) return false;
    const canonical = canonicalizeJson(this.toDict(false));
    return ed25519Verify(publicKey, new TextEncoder().encode(canonical), this.data.proof.proofValue);
  }

  toJSON(): string {
    return canonicalizeJson(this.toDict());
  }

  static fromJSON(json: string): ReputationSummary {
    const raw = JSON.parse(json) as ReputationSummaryData;
    return new ReputationSummary(raw);
  }
}
