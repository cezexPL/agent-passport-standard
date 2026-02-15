import { canonicalizeJson, ed25519Sign, ed25519Verify, generateKeyPair } from './crypto.js';

export interface AttestationData {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: {
    id: string;
    type: string;
    claims: Record<string, unknown>;
  };
  proof?: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
  };
}

export class Attestation {
  data: AttestationData;

  constructor(data: AttestationData) {
    this.data = data;
  }

  toDict(includeProof = true): Record<string, unknown> {
    const d: Record<string, unknown> = {
      '@context': this.data['@context'],
      type: this.data.type,
      issuer: this.data.issuer,
      issuanceDate: this.data.issuanceDate,
      credentialSubject: this.data.credentialSubject,
    };
    if (this.data.expirationDate) {
      d.expirationDate = this.data.expirationDate;
    }
    if (includeProof && this.data.proof) {
      d.proof = this.data.proof;
    }
    return d;
  }

  private messageBytes(): Uint8Array {
    const d = this.toDict(false);
    const canonical = canonicalizeJson(d);
    return new TextEncoder().encode(canonical);
  }

  async sign(privateKey: Uint8Array): Promise<void> {
    const msg = this.messageBytes();
    const sig = await ed25519Sign(privateKey, msg);
    this.data.proof = {
      type: 'Ed25519Signature2020',
      created: this.data.issuanceDate,
      verificationMethod: this.data.issuer + '#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: sig,
    };
  }

  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.data.proof) return false;

    // Check expiry
    if (this.data.expirationDate) {
      const exp = new Date(this.data.expirationDate);
      if (new Date() > exp) return false;
    }

    const proof = this.data.proof;
    const saved = this.data.proof;
    this.data.proof = undefined;
    const msg = this.messageBytes();
    this.data.proof = saved;

    return ed25519Verify(publicKey, msg, proof.proofValue);
  }
}

export async function createAttestation(
  issuerDID: string,
  subjectDID: string,
  atType: string,
  claims: Record<string, unknown>,
  privateKey: Uint8Array,
  expirationDate?: string,
): Promise<Attestation> {
  const now = new Date().toISOString();
  const att = new Attestation({
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://agentpassport.org/v0.2/attestation',
    ],
    type: ['VerifiableCredential', 'AgentAttestation'],
    issuer: issuerDID,
    issuanceDate: now,
    expirationDate,
    credentialSubject: { id: subjectDID, type: atType, claims },
  });
  await att.sign(privateKey);
  return att;
}

export class AttestationRegistry {
  private issuers = new Map<string, Uint8Array>();

  registerIssuer(did: string, publicKey: Uint8Array): void {
    this.issuers.set(did, publicKey);
  }

  removeIssuer(did: string): void {
    this.issuers.delete(did);
  }

  isTrusted(did: string): boolean {
    return this.issuers.has(did);
  }

  getPublicKey(did: string): Uint8Array | undefined {
    return this.issuers.get(did);
  }

  async verifyFromRegistry(att: Attestation): Promise<boolean> {
    const pk = this.getPublicKey(att.data.issuer);
    if (!pk) throw new Error(`Issuer ${att.data.issuer} not trusted`);
    return att.verify(pk);
  }
}
