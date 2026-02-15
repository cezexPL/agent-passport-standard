import { describe, it, expect } from 'vitest';
import { ReputationSummary } from '../src/reputation.js';
import { generateKeyPair } from '../src/crypto.js';

describe('ReputationSummary', () => {
  it('creates a reputation summary', () => {
    const r = new ReputationSummary({
      agent_did: 'did:key:z6MkTest',
      generated_at: '2025-01-01T00:00:00Z',
      total_jobs: 10,
      successful_jobs: 9,
      failed_jobs: 1,
      average_score: 0.95,
      trust_tier: 2,
      attestation_count: 3,
      categories: {},
    });
    expect(r.data.total_jobs).toBe(10);
  });

  it('sign and verify', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const r = new ReputationSummary({
      agent_did: 'did:key:z6MkTest',
      generated_at: '2025-01-01T00:00:00Z',
      total_jobs: 5,
      successful_jobs: 5,
      failed_jobs: 0,
      average_score: 1.0,
      trust_tier: 1,
      attestation_count: 0,
      categories: {},
    });
    await r.sign(privateKey);
    expect(r.data.proof).not.toBeNull();
    expect(await r.verify(publicKey)).toBe(true);
  });

  it('roundtrip JSON', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const r = new ReputationSummary({
      agent_did: 'did:key:z6MkTest',
      generated_at: '2025-01-01T00:00:00Z',
      total_jobs: 5,
      successful_jobs: 5,
      failed_jobs: 0,
      average_score: 1.0,
      trust_tier: 1,
      attestation_count: 0,
      categories: {},
    });
    await r.sign(privateKey);
    const json = r.toJSON();
    const r2 = ReputationSummary.fromJSON(json);
    expect(r2.data.agent_did).toBe('did:key:z6MkTest');
    expect(await r2.verify(publicKey)).toBe(true);
  });
});
