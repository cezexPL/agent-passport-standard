import { describe, it, expect } from 'vitest';
import { computeReputation, computeDecay } from '../src/sybil.js';

describe('Sybil Resistance & Reputation (§21)', () => {
  it('returns zero score for empty attestations', () => {
    const rep = computeReputation('did:key:z6MkAgent', []);
    expect(rep.score).toBe(0);
    expect(rep.agentDid).toBe('did:key:z6MkAgent');
  });

  it('computes decay close to 1 for recent timestamps', () => {
    const now = new Date().toISOString();
    const decay = computeDecay(now);
    expect(decay).toBeGreaterThan(0.99);
    expect(decay).toBeLessThanOrEqual(1);
  });

  it('computes decay < 1 for old timestamps', () => {
    const oldDate = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
    const decay = computeDecay(oldDate, 0.01);
    expect(decay).toBeLessThan(0.05); // e^(-0.01*365) ≈ 0.026
  });

  it('computes reputation for recent attestations', () => {
    const now = new Date().toISOString();
    const rep = computeReputation('did:key:z6MkAgent', [
      { weight: 0.8, timestamp: now },
      { weight: 0.9, timestamp: now },
    ]);
    expect(rep.score).toBeGreaterThan(0.8);
    expect(rep.score).toBeLessThanOrEqual(1);
    expect(rep.components.rawSum).toBeGreaterThan(0);
  });

  it('score is clamped to [0, 1]', () => {
    const now = new Date().toISOString();
    const rep = computeReputation('did:key:z6MkAgent', [
      { weight: 5, timestamp: now },
    ]);
    expect(rep.score).toBeLessThanOrEqual(1);
  });

  it('serializes to JSON', () => {
    const now = new Date().toISOString();
    const rep = computeReputation('did:key:z6MkAgent', [
      { weight: 0.5, timestamp: now },
    ]);
    const parsed = JSON.parse(JSON.stringify(rep));
    expect(parsed.agentDid).toBe('did:key:z6MkAgent');
    expect(typeof parsed.score).toBe('number');
  });
});
