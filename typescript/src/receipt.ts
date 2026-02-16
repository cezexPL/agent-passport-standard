import type { WorkReceiptData, ReceiptConfig, ReceiptEvent } from './types.js';
import { canonicalizeJson, ed25519Sign, ed25519Verify, hashExcludingFields } from './crypto.js';
import { validateReceipt as validateReceiptSchema } from './validate.js';

export class WorkReceipt {
  data: WorkReceiptData;

  private constructor(data: WorkReceiptData) {
    this.data = data;
  }

  static create(cfg: ReceiptConfig): WorkReceipt {
    if (!cfg.receiptId || !cfg.jobId) throw new Error('receipt_id and job_id are required');
    if (!cfg.agentDID || !cfg.clientDID) throw new Error('agent_did and client_did are required');

    const data: WorkReceiptData = {
      '@context': 'https://agentpassport.org/v0.1',
      spec_version: '1.0.0',
      type: 'WorkReceipt',
      receipt_id: cfg.receiptId,
      job_id: cfg.jobId,
      agent_did: cfg.agentDID,
      client_did: cfg.clientDID,
      platform_did: cfg.platformDID,
      agent_snapshot: cfg.agentSnapshot,
      events: [],
      receipt_hash: '',
    };

    return new WorkReceipt(data);
  }

  validate(): void {
    validateReceiptSchema(this.data);
  }

  static fromJson(json: string, validate = true): WorkReceipt {
    const data = JSON.parse(json) as WorkReceiptData;
    if (validate) validateReceiptSchema(data);
    return new WorkReceipt(data);
  }

  toJson(): string {
    return canonicalizeJson(this.data);
  }

  addEvent(event: ReceiptEvent): void {
    if (!event.type) throw new Error('event type is required');
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    }
    this.data.events.push(event);
  }

  hash(): string {
    return hashExcludingFields(this.data, 'proof', 'receipt_hash');
  }

  async sign(privateKey: Uint8Array): Promise<void> {
    this.data.receipt_hash = this.hash();

    const savedProof = this.data.proof;
    this.data.proof = null;

    try {
      const canonical = canonicalizeJson(this.data);
      const sig = await ed25519Sign(privateKey, new TextEncoder().encode(canonical));
      const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

      this.data.proof = {
        type: 'Ed25519Signature2020',
        created: now,
        verificationMethod: this.data.agent_did + '#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: sig,
      };
    } catch (e) {
      this.data.proof = savedProof;
      throw e;
    }
  }

  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.data.proof) throw new Error('no proof present');

    const proof = this.data.proof;
    this.data.proof = null;

    try {
      const canonical = canonicalizeJson(this.data);
      return await ed25519Verify(publicKey, new TextEncoder().encode(canonical), proof.proofValue);
    } finally {
      this.data.proof = proof;
    }
  }
}
