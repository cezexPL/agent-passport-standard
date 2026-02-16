import { canonicalizeJson, ed25519Sign, ed25519Verify } from './crypto.js';
import { AgentPassport } from './passport.js';
import { WorkReceipt } from './receipt.js';
import type { Proof } from './types.js';

export interface AgentPassportBundleData {
  type: string;
  passport: Record<string, unknown>;
  work_receipts: Record<string, unknown>[];
  attestations: Record<string, unknown>[];
  reputation_summary: Record<string, unknown> | null;
  anchor_proofs: Record<string, unknown>[];
  proof?: Proof | null;
}

export class AgentPassportBundle {
  data: AgentPassportBundleData;

  constructor(data: Partial<AgentPassportBundleData> = {}) {
    this.data = {
      type: 'AgentPassportBundle',
      passport: data.passport || {},
      work_receipts: data.work_receipts || [],
      attestations: data.attestations || [],
      reputation_summary: data.reputation_summary || null,
      anchor_proofs: data.anchor_proofs || [],
      proof: data.proof || null,
    };
  }

  private toDict(includeProof = true): Record<string, unknown> {
    const d: Record<string, unknown> = {
      type: this.data.type,
      passport: this.data.passport,
      work_receipts: this.data.work_receipts,
      attestations: this.data.attestations,
      reputation_summary: this.data.reputation_summary,
      anchor_proofs: this.data.anchor_proofs,
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
    const agentDid = (this.data.passport as Record<string, unknown>).id as string || '';
    this.data.proof = {
      type: 'Ed25519Signature2020',
      created: now,
      verificationMethod: agentDid + '#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: sig,
    };
  }

  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.data.proof) return false;
    const canonical = canonicalizeJson(this.toDict(false));
    return ed25519Verify(publicKey, new TextEncoder().encode(canonical), this.data.proof.proofValue);
  }

  async verifyAll(publicKey: Uint8Array): Promise<boolean> {
    if (!(await this.verify(publicKey))) return false;

    // Verify passport
    const passport = AgentPassport.fromJson(JSON.stringify(this.data.passport), false);
    if (passport.data.proof) {
      if (!(await passport.verify(publicKey))) return false;
    }

    // Verify receipts
    for (const rData of this.data.work_receipts) {
      const receipt = WorkReceipt.fromJson(JSON.stringify(rData), false);
      if (receipt.data.proof) {
        if (!(await receipt.verify(publicKey))) return false;
      }
    }

    return true;
  }

  toJSON(): string {
    return canonicalizeJson(this.toDict());
  }

  static fromJSON(json: string): AgentPassportBundle {
    const raw = JSON.parse(json) as AgentPassportBundleData;
    return new AgentPassportBundle(raw);
  }
}
