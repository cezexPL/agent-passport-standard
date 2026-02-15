import { describe, it, expect } from 'vitest';
import {
  timingSafeEqual, validateDid, validateHash, validateSignature,
  validateTimestamp, validateVersion, validateTrustTier, validateAttestationCount,
  keccak256, snapshotHash, ed25519Sign, ed25519Verify, generateKeyPair,
  canonicalizeJson, MerkleTree,
} from '../src/index.js';
import { AgentPassport } from '../src/passport.js';
import { WorkReceipt } from '../src/receipt.js';
import type { PassportConfig, Skill, Soul, Policies, Lineage } from '../src/types.js';

function testConfig(): PassportConfig {
  return {
    id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
    publicKey: 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
    ownerDID: 'did:key:z6MkpOwnerABCDEFGHIJKLMNOPQRSTUVWXYZ12345',
    skills: [{
      name: 'test', version: '1.0.0', description: 'Test',
      capabilities: ['test'], hash: '0x' + '00'.repeat(32),
    }],
    soul: {
      personality: 'focused', work_style: 'test', constraints: ['none'],
      hash: '0x' + '00'.repeat(32), frozen: false,
    },
    policies: { policy_set_hash: '0x' + '00'.repeat(32), summary: ['can_bid'] },
    lineage: { kind: 'single', parents: [], generation: 0 },
  };
}

// --- Timing-Safe Comparison ---
describe('timingSafeEqual', () => {
  it('returns true for equal strings', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
  });
  it('returns false for different strings', () => {
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
  });
  it('returns false for different lengths', () => {
    expect(timingSafeEqual('short', 'longer')).toBe(false);
  });
});

// --- Validation ---
describe('validation', () => {
  it('validates valid DID', () => {
    expect(() => validateDid('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH')).not.toThrow();
  });
  it('rejects empty DID', () => {
    expect(() => validateDid('')).toThrow();
  });
  it('rejects invalid DID', () => {
    expect(() => validateDid('not-a-did')).toThrow();
    expect(() => validateDid('did:key:abc')).toThrow();
  });
  it('validates valid hash', () => {
    expect(() => validateHash('0x' + 'ab'.repeat(32))).not.toThrow();
  });
  it('rejects invalid hash', () => {
    expect(() => validateHash('')).toThrow();
    expect(() => validateHash('0x123')).toThrow();
  });
  it('validates valid signature', () => {
    expect(() => validateSignature('ab'.repeat(64))).not.toThrow();
  });
  it('rejects invalid signature', () => {
    expect(() => validateSignature('')).toThrow();
    expect(() => validateSignature('short')).toThrow();
  });
  it('validates valid timestamp', () => {
    expect(() => validateTimestamp('2026-02-15T12:00:00Z')).not.toThrow();
  });
  it('rejects invalid timestamp', () => {
    expect(() => validateTimestamp('')).toThrow();
    expect(() => validateTimestamp('not-a-date')).toThrow();
  });
  it('validates version', () => {
    expect(() => validateVersion(1)).not.toThrow();
    expect(() => validateVersion(0)).toThrow();
    expect(() => validateVersion(-1)).toThrow();
  });
  it('validates trust tier', () => {
    expect(() => validateTrustTier(0)).not.toThrow();
    expect(() => validateTrustTier(3)).not.toThrow();
    expect(() => validateTrustTier(-1)).toThrow();
    expect(() => validateTrustTier(4)).toThrow();
    expect(() => validateTrustTier(999)).toThrow();
  });
  it('validates attestation count', () => {
    expect(() => validateAttestationCount(0)).not.toThrow();
    expect(() => validateAttestationCount(-1)).toThrow();
  });
});

// --- Signature Forgery ---
describe('signature forgery', () => {
  it('tampered passport fails verification', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const p = await AgentPassport.create(testConfig());
    await p.sign(privateKey);
    p.data.snapshot.version = 999;
    expect(await p.verify(publicKey)).toBe(false);
  });
});

// --- Hash Manipulation ---
describe('hash manipulation', () => {
  it('different content produces different hashes', () => {
    const h1 = snapshotHash({ skill: 'go', version: 1 });
    const h2 = snapshotHash({ skill: 'go', version: 2 });
    expect(h1).not.toBe(h2);
  });
});

// --- Replay Attack ---
describe('replay attack', () => {
  it('stolen proof fails on different passport', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const p1 = await AgentPassport.create(testConfig());
    await p1.sign(privateKey);
    const stolenProof = p1.data.proof;

    const cfg2 = testConfig();
    cfg2.id = 'did:key:z6MkDIFFERENT1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const p2 = await AgentPassport.create(cfg2);
    p2.data.proof = stolenProof;
    expect(await p2.verify(publicKey)).toBe(false);
  });
});

// --- Null/Empty Injection ---
describe('null/empty injection', () => {
  it('rejects empty id', async () => {
    const cfg = testConfig();
    cfg.id = '';
    await expect(AgentPassport.create(cfg)).rejects.toThrow();
  });
  it('rejects empty publicKey', async () => {
    const cfg = testConfig();
    cfg.publicKey = '';
    await expect(AgentPassport.create(cfg)).rejects.toThrow();
  });
  it('rejects empty ownerDID', async () => {
    const cfg = testConfig();
    cfg.ownerDID = '';
    await expect(AgentPassport.create(cfg)).rejects.toThrow();
  });
});

// --- Oversized Input ---
describe('oversized input', () => {
  it('handles 10K skills without crash', async () => {
    const skills: Skill[] = [];
    for (let i = 0; i < 10000; i++) {
      skills.push({
        name: `skill-${i}`, version: '1.0.0', description: 'x',
        capabilities: ['test'], hash: '0x' + '00'.repeat(32),
      });
    }
    const cfg = testConfig();
    cfg.skills = skills;
    const p = await AgentPassport.create(cfg);
    expect(p.data.snapshot.hash).toBeTruthy();
  });
});

// --- Unicode Edge Cases ---
describe('unicode edge cases', () => {
  it('emoji in skills', () => {
    expect(snapshotHash({ skill: '🤖' })).toMatch(/^0x/);
  });
  it('RTL text', () => {
    expect(snapshotHash({ skill: 'مرحبا' })).toMatch(/^0x/);
  });
  it('null bytes', () => {
    expect(snapshotHash({ skill: 'a\x00b' })).toMatch(/^0x/);
  });
});

// --- Integer Overflow ---
describe('integer overflow', () => {
  it('rejects trust tier 999', () => {
    expect(() => validateTrustTier(999)).toThrow();
  });
  it('rejects negative attestation', () => {
    expect(() => validateAttestationCount(-1)).toThrow();
  });
});

// --- Proof Stripping ---
describe('proof stripping', () => {
  it('verify without proof throws', async () => {
    const { publicKey } = generateKeyPair();
    const p = await AgentPassport.create(testConfig());
    await expect(p.verify(publicKey)).rejects.toThrow('no proof present');
  });
});

// --- Key Mismatch ---
describe('key mismatch', () => {
  it('wrong key returns false', async () => {
    const { privateKey } = generateKeyPair();
    const { publicKey: pub2 } = generateKeyPair();
    const p = await AgentPassport.create(testConfig());
    await p.sign(privateKey);
    expect(await p.verify(pub2)).toBe(false);
  });
});

// --- Frozen Mutation ---
describe('frozen mutation', () => {
  it('addSkill throws when frozen', async () => {
    const p = await AgentPassport.create(testConfig());
    p.data.snapshot.skills.frozen = true;
    expect(() => p.addSkill({
      name: 'new', version: '1.0.0', description: 'x',
      capabilities: ['test'], hash: '0x' + '00'.repeat(32),
    })).toThrow('skills are frozen');
  });
});

// --- Canonical JSON Edge Cases ---
describe('canonical JSON edge cases', () => {
  it('null/true/false', () => {
    expect(canonicalizeJson({ a: null, b: true, c: false }))
      .toBe('{"a":null,"b":true,"c":false}');
  });
  it('nested unsorted keys', () => {
    expect(canonicalizeJson({ z: { b: 2, a: 1 }, a: 'first' }))
      .toBe('{"a":"first","z":{"a":1,"b":2}}');
  });
  it('mixed array', () => {
    expect(canonicalizeJson([1, 'two', true, null, { b: 2, a: 1 }]))
      .toBe('[1,"two",true,null,{"a":1,"b":2}]');
  });
  it('special chars', () => {
    const result = canonicalizeJson({ quote: 'a"b', backslash: 'a\\b', newline: 'a\nb' });
    expect(result).toContain('"a\\"b"');
    expect(result).toContain('"a\\\\b"');
    expect(result).toContain('"a\\nb"');
  });
  it('numbers', () => {
    const result = canonicalizeJson({ zero: 0, one: 1, neg: -1, float: 1.5 });
    expect(result).toContain('"float":1.5');
    expect(result).toContain('"neg":-1');
  });
  it('emoji string', () => {
    const result = canonicalizeJson({ emoji: '😀' });
    expect(result).toContain('😀');
  });
  it('deterministic', () => {
    const obj = { z: 1, a: 2, m: { c: 3, b: 4 } };
    expect(canonicalizeJson(obj)).toBe(canonicalizeJson(obj));
  });
});

// --- Merkle Timing-Safe ---
describe('merkle timing-safe', () => {
  it('rejects wrong root', () => {
    const enc = new TextEncoder();
    const leaves = [0, 1, 2, 3].map(i => keccak256(enc.encode(`leaf-${i}`)));
    const tree = new MerkleTree(leaves);
    const root = tree.root();
    const proof = tree.proof(0);
    expect(MerkleTree.verifyProof(leaves[0], root, proof, 0)).toBe(true);
    const fakeRoot = '0x' + '00'.repeat(32);
    expect(MerkleTree.verifyProof(leaves[0], fakeRoot, proof, 0)).toBe(false);
  });
});
