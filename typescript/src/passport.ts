import type { AgentPassportData, PassportConfig, Proof, Skill } from './types.js';
import { canonicalizeJson, ed25519Sign, ed25519Verify, snapshotHash, hashExcludingFields } from './crypto.js';
import { validatePassport as validatePassportSchema } from './validate.js';

export class AgentPassport {
  data: AgentPassportData;

  private constructor(data: AgentPassportData) {
    this.data = data;
  }

  static async create(cfg: PassportConfig): Promise<AgentPassport> {
    if (!cfg.id) throw new Error('id is required');
    if (!cfg.publicKey) throw new Error('public_key is required');
    if (!cfg.ownerDID) throw new Error('owner_did is required');

    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

    const data: AgentPassportData = {
      '@context': 'https://agentpassport.org/v0.1',
      spec_version: '0.1.0',
      type: 'AgentPassport',
      id: cfg.id,
      keys: {
        signing: { algorithm: 'Ed25519', public_key: cfg.publicKey },
        encryption: null,
      },
      genesis_owner: { id: cfg.ownerDID, bound_at: now, immutable: true },
      current_owner: { id: cfg.ownerDID, transferred_at: null },
      snapshot: {
        version: 1,
        hash: '',
        prev_hash: null,
        created_at: now,
        skills: { entries: cfg.skills, frozen: false },
        soul: cfg.soul,
        policies: cfg.policies,
      },
      lineage: cfg.lineage,
    };

    if (cfg.evmAddress) {
      data.keys.evm = { address: cfg.evmAddress };
    }

    // Compute snapshot hash
    const snapshotContent = {
      skills: data.snapshot.skills,
      soul: data.snapshot.soul,
      policies: data.snapshot.policies,
    };
    data.snapshot.hash = snapshotHash(snapshotContent);

    return new AgentPassport(data);
  }

  validate(): void {
    validatePassportSchema(this.data);
  }

  static fromJson(json: string, validate = true): AgentPassport {
    const data = JSON.parse(json) as AgentPassportData;
    if (validate) validatePassportSchema(data);
    return new AgentPassport(data);
  }

  toJson(): string {
    return canonicalizeJson(this.data);
  }

  hash(): string {
    return hashExcludingFields(this.data, 'proof');
  }

  async sign(privateKey: Uint8Array): Promise<void> {
    const savedProof = this.data.proof;
    this.data.proof = null;

    try {
      const canonical = canonicalizeJson(this.data);
      const sig = await ed25519Sign(privateKey, new TextEncoder().encode(canonical));
      const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

      this.data.proof = {
        type: 'Ed25519Signature2020',
        created: now,
        verification_method: this.data.id + '#key-1',
        proof_purpose: 'assertionMethod',
        proof_value: sig,
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
      return await ed25519Verify(publicKey, new TextEncoder().encode(canonical), proof.proof_value);
    } finally {
      this.data.proof = proof;
    }
  }

  /** Check if skills are frozen; throws if trying to add to frozen skills */
  addSkill(skill: Skill): void {
    if (this.data.snapshot.skills.frozen) {
      throw new Error('skills are frozen');
    }
    this.data.snapshot.skills.entries.push(skill);
    // Recompute snapshot hash
    const snapshotContent = {
      skills: this.data.snapshot.skills,
      soul: this.data.snapshot.soul,
      policies: this.data.snapshot.policies,
    };
    this.data.snapshot.hash = snapshotHash(snapshotContent);
  }

  /** Create a new snapshot version, chaining prev_hash */
  newSnapshot(): void {
    const prevHash = this.data.snapshot.hash;
    this.data.snapshot.version += 1;
    this.data.snapshot.prev_hash = prevHash;
    this.data.snapshot.created_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

    const snapshotContent = {
      skills: this.data.snapshot.skills,
      soul: this.data.snapshot.soul,
      policies: this.data.snapshot.policies,
    };
    this.data.snapshot.hash = snapshotHash(snapshotContent);
  }
}
