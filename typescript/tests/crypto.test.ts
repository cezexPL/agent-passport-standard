import { describe, it, expect } from 'vitest';
import { canonicalizeJson, keccak256, ed25519Sign, ed25519Verify, generateKeyPair, MerkleTree } from '../src/crypto.js';

describe('canonicalizeJson', () => {
  it('sorts keys lexicographically', () => {
    expect(canonicalizeJson({ z: 1, a: 2, m: 3 })).toBe('{"a":2,"m":3,"z":1}');
  });

  it('handles nested objects', () => {
    const result = canonicalizeJson({ b: { z: 1, a: 2 }, a: 1 });
    expect(result).toBe('{"a":1,"b":{"a":2,"z":1}}');
  });

  it('handles arrays', () => {
    expect(canonicalizeJson({ a: [3, 2, 1] })).toBe('{"a":[3,2,1]}');
  });

  it('handles null', () => {
    expect(canonicalizeJson(null)).toBe('null');
  });
});

describe('keccak256', () => {
  it('hashes empty object correctly', () => {
    const hash = keccak256(new TextEncoder().encode('{}'));
    expect(hash).toBe('0xb48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d');
  });
});

describe('ed25519', () => {
  it('sign and verify roundtrip', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const message = new TextEncoder().encode('hello world');
    const sig = await ed25519Sign(privateKey, message);
    const valid = await ed25519Verify(publicKey, message, sig);
    expect(valid).toBe(true);
  });

  it('rejects tampered message', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const message = new TextEncoder().encode('hello world');
    const sig = await ed25519Sign(privateKey, message);
    const valid = await ed25519Verify(publicKey, new TextEncoder().encode('tampered'), sig);
    expect(valid).toBe(false);
  });
});

describe('MerkleTree', () => {
  it('builds tree with 4 leaves and verifies proofs', () => {
    const leaves = [
      '0x0000000000000000000000000000000000000000000000000000000000000001',
      '0x0000000000000000000000000000000000000000000000000000000000000002',
      '0x0000000000000000000000000000000000000000000000000000000000000003',
      '0x0000000000000000000000000000000000000000000000000000000000000004',
    ];
    const tree = new MerkleTree(leaves);
    expect(tree.layers.length).toBe(3); // depth 2 => 3 layers
    expect(tree.root()).toBeTruthy();

    // Verify proof for each leaf
    for (let i = 0; i < 4; i++) {
      const proof = tree.proof(i);
      expect(MerkleTree.verifyProof(leaves[i], tree.root(), proof, i)).toBe(true);
    }
  });

  it('rejects invalid proof', () => {
    const leaves = [
      '0x0000000000000000000000000000000000000000000000000000000000000001',
      '0x0000000000000000000000000000000000000000000000000000000000000002',
      '0x0000000000000000000000000000000000000000000000000000000000000003',
      '0x0000000000000000000000000000000000000000000000000000000000000004',
    ];
    const tree = new MerkleTree(leaves);
    const proof = tree.proof(0);
    // Wrong leaf
    expect(MerkleTree.verifyProof(leaves[2], tree.root(), proof, 0)).toBe(false);
  });

  it('handles empty leaves', () => {
    const tree = new MerkleTree([]);
    expect(tree.root()).toBe('');
  });
});
