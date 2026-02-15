import { describe, it, expect } from 'vitest';
import { AgentPassportBundle } from '../src/bundle.js';
import { generateKeyPair } from '../src/crypto.js';

function makeBundle() {
  return new AgentPassportBundle({
    passport: { id: 'did:key:z6MkTest', type: 'AgentPassport', keys: {} },
    work_receipts: [{ receipt_id: 'r1', type: 'WorkReceipt' }],
    attestations: [{ issuer: 'did:key:z6MkIssuer' }],
    reputation_summary: { agent_did: 'did:key:z6MkTest', total_jobs: 5 },
    anchor_proofs: [],
  });
}

describe('AgentPassportBundle', () => {
  it('creates a bundle', () => {
    const b = makeBundle();
    expect((b.data.passport as any).id).toBe('did:key:z6MkTest');
    expect(b.data.work_receipts.length).toBe(1);
  });

  it('sign and verify', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const b = makeBundle();
    await b.sign(privateKey);
    expect(b.data.proof).not.toBeNull();
    expect(await b.verify(publicKey)).toBe(true);
  });

  it('verify fails with wrong key', async () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const b = makeBundle();
    await b.sign(kp1.privateKey);
    expect(await b.verify(kp2.publicKey)).toBe(false);
  });

  it('roundtrip JSON', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const b = makeBundle();
    await b.sign(privateKey);
    const json = b.toJSON();
    const b2 = AgentPassportBundle.fromJSON(json);
    expect((b2.data.passport as any).id).toBe('did:key:z6MkTest');
    expect(await b2.verify(publicKey)).toBe(true);
  });
});
