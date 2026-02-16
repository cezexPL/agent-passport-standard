/**
 * Performance benchmarks for APS TypeScript SDK.
 *
 * Run with: npx vitest run tests/benchmark.test.ts
 * For vitest bench mode: npx vitest bench tests/benchmark.test.ts
 */
import { describe, it, expect } from 'vitest';
import {
  canonicalizeJson,
  keccak256,
  keccak256Bytes,
  snapshotHash,
  ed25519Sign,
  ed25519Verify,
  generateKeyPair,
  MerkleTree,
} from '../src/index.js';
import { AgentPassport } from '../src/passport.js';
import { bytesToHex } from '@noble/hashes/utils';
import type { PassportConfig } from '../src/types.js';

function makeConfig(): { cfg: PassportConfig; pub: Uint8Array; priv: Uint8Array } {
  const { publicKey, privateKey } = generateKeyPair();
  const cfg: PassportConfig = {
    id: 'did:key:z6MkBenchTest1234567890abcdefghijklmnop',
    publicKey: bytesToHex(publicKey),
    ownerDID: 'did:key:z6MkBenchOwner1234567890abcdefghijklmno',
    skills: [{
      name: 'ts-backend', version: '1.0.0',
      description: 'TypeScript backend', capabilities: ['code_write'],
      hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
    }],
    soul: {
      personality: 'Efficient', work_style: 'Systematic',
      constraints: ['no-external-calls'],
      hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      frozen: false,
    },
    policies: {
      policy_set_hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      summary: ['read-only'],
    },
    lineage: { kind: 'original', parents: [], generation: 0 },
  };
  return { cfg, pub: publicKey, priv: privateKey };
}

function measure(fn: () => void, iterations: number): { meanUs: number; minUs: number; maxUs: number } {
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    times.push((performance.now() - start) * 1000); // µs
  }
  const mean = times.reduce((a, b) => a + b) / times.length;
  return { meanUs: mean, minUs: Math.min(...times), maxUs: Math.max(...times) };
}

async function measureAsync(fn: () => Promise<void>, iterations: number) {
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    times.push((performance.now() - start) * 1000);
  }
  const mean = times.reduce((a, b) => a + b) / times.length;
  return { meanUs: mean, minUs: Math.min(...times), maxUs: Math.max(...times) };
}

describe('benchmarks', () => {
  it('keccak256', () => {
    const data = new TextEncoder().encode('The quick brown fox jumps over the lazy dog');
    const r = measure(() => keccak256(data), 5000);
    console.log(`keccak256: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(1000);
  });

  it('canonicalizeJson', () => {
    const r = measure(() => {
      canonicalizeJson({ z: 'last', a: 42, m: ['x', 'y'], nested: { b: 2, a: 1 } });
    }, 5000);
    console.log(`canonicalizeJson: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(1000);
  });

  it('snapshotHash', () => {
    const r = measure(() => {
      snapshotHash({
        skills: { entries: [], frozen: false },
        soul: { personality: 'test', hash: '0x00' },
        policies: { policy_set_hash: '0x00', summary: [] },
      });
    }, 3000);
    console.log(`snapshotHash: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(5000);
  });

  it('ed25519 sign', async () => {
    const { privateKey } = generateKeyPair();
    const data = new TextEncoder().encode('bench');
    const r = await measureAsync(async () => { await ed25519Sign(privateKey, data); }, 1000);
    console.log(`ed25519Sign: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(10000);
  });

  it('ed25519 verify', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const data = new TextEncoder().encode('bench');
    const sig = await ed25519Sign(privateKey, data);
    const r = await measureAsync(async () => { await ed25519Verify(publicKey, data, sig); }, 200);
    console.log(`ed25519Verify: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(10000);
  });

  it('passport create', async () => {
    const { cfg } = makeConfig();
    const r = await measureAsync(async () => { await AgentPassport.create(cfg); }, 1000);
    console.log(`passport create: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(50000);
  });

  it('passport sign+verify', async () => {
    const { cfg, pub, priv } = makeConfig();
    const p = await AgentPassport.create(cfg);
    const r = await measureAsync(async () => {
      await p.sign(priv);
      await p.verify(pub);
    }, 500);
    console.log(`passport sign+verify: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(100000);
  });

  it('merkle tree 1000 leaves', () => {
    const leaves: string[] = [];
    for (let i = 0; i < 1000; i++) {
      leaves.push(keccak256(new TextEncoder().encode(`leaf-${i}`)));
    }
    const r = measure(() => {
      const mt = new MerkleTree(leaves);
      mt.root();
    }, 50);
    console.log(`merkle 1000: mean=${r.meanUs.toFixed(1)}µs`);
    expect(r.meanUs).toBeLessThan(5000000);
  });
});
