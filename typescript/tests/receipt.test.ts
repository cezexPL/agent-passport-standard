import { describe, it, expect } from 'vitest';
import { WorkReceipt } from '../src/receipt.js';
import { generateKeyPair, MerkleTree } from '../src/crypto.js';

describe('WorkReceipt', () => {
  it('full lifecycle (claim→submit→verify→payout)', () => {
    const receipt = WorkReceipt.create({
      receiptId: 'r-001',
      jobId: 'j-001',
      agentDID: 'did:key:z6MkAgent',
      clientDID: 'did:key:z6MkClient',
      agentSnapshot: { version: 1, hash: '0xaaa' },
    });

    receipt.addEvent({ type: 'claim', timestamp: '2026-01-01T00:00:00Z', payload_hash: '0x01', signature: 'sig1' });
    receipt.addEvent({ type: 'submit', timestamp: '2026-01-01T01:00:00Z', payload_hash: '0x02', signature: 'sig2' });
    receipt.addEvent({
      type: 'verify', timestamp: '2026-01-01T01:30:00Z', payload_hash: '0x03', signature: 'sig3',
      result: { status: 'accepted', score: 90 },
    });
    receipt.addEvent({
      type: 'payout', timestamp: '2026-01-01T02:00:00Z', payload_hash: '0x04', signature: 'sig4',
      amount: { value: 100, unit: 'points' },
    });

    expect(receipt.data.events.length).toBe(4);
    expect(receipt.data.events[2].result?.status).toBe('accepted');
    expect(receipt.hash()).toBeTruthy();
  });

  it('sign → verify roundtrip', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const receipt = WorkReceipt.create({
      receiptId: 'r-002',
      jobId: 'j-002',
      agentDID: 'did:key:z6MkAgent',
      clientDID: 'did:key:z6MkClient',
      agentSnapshot: { version: 1, hash: '0xaaa' },
    });

    receipt.addEvent({ type: 'claim', timestamp: '2026-01-01T00:00:00Z', payload_hash: '0x01', signature: 'sig1' });
    await receipt.sign(privateKey);

    expect(receipt.data.proof).toBeTruthy();
    expect(receipt.data.receipt_hash).toBeTruthy();

    const valid = await receipt.verify(publicKey);
    expect(valid).toBe(true);
  });

  it('batch proof with merkle tree', () => {
    const receipts: WorkReceipt[] = [];
    for (let i = 0; i < 4; i++) {
      const r = WorkReceipt.create({
        receiptId: `r-${i}`,
        jobId: `j-${i}`,
        agentDID: 'did:key:z6MkAgent',
        clientDID: 'did:key:z6MkClient',
        agentSnapshot: { version: 1, hash: '0xaaa' },
      });
      r.addEvent({ type: 'claim', timestamp: '2026-01-01T00:00:00Z', payload_hash: `0x0${i}`, signature: `sig${i}` });
      receipts.push(r);
    }

    const hashes = receipts.map(r => r.hash());
    const tree = new MerkleTree(hashes);

    for (let i = 0; i < 4; i++) {
      const proof = tree.proof(i);
      expect(MerkleTree.verifyProof(hashes[i], tree.root(), proof, i)).toBe(true);
    }
  });
});
