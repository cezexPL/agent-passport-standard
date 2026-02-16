import { describe, it, expect } from 'vitest';
import { createProvenance, validateHashFormat } from '../src/provenance.js';

const VALID_HASH = 'sha256:' + 'a'.repeat(64);
const KECCAK_HASH = 'keccak256:' + 'b'.repeat(64);

describe('Provenance (§18)', () => {
  it('validates correct hash formats', () => {
    expect(validateHashFormat(VALID_HASH)).toBe(true);
    expect(validateHashFormat(KECCAK_HASH)).toBe(true);
  });

  it('rejects invalid hash formats', () => {
    expect(validateHashFormat('md5:abc')).toBe(false);
    expect(validateHashFormat('sha256:tooshort')).toBe(false);
    expect(validateHashFormat('')).toBe(false);
  });

  it('creates provenance with valid hashes', () => {
    const p = createProvenance({
      artifactDid: 'did:key:z6MkArtifact',
      creatorDid: 'did:key:z6MkCreator',
      hashChain: [VALID_HASH, KECCAK_HASH],
    });
    expect(p.specVersion).toBe('1.1');
    expect(p.hashChain).toHaveLength(2);
    expect(p.parentHash).toBeNull();
  });

  it('throws on invalid hash in chain', () => {
    expect(() => createProvenance({
      artifactDid: 'did:key:z6MkArtifact',
      creatorDid: 'did:key:z6MkCreator',
      hashChain: ['bad-hash'],
    })).toThrow('Invalid hash format');
  });

  it('serializes to JSON', () => {
    const p = createProvenance({
      artifactDid: 'did:key:z6MkArtifact',
      creatorDid: 'did:key:z6MkCreator',
      hashChain: [VALID_HASH],
      parentHash: KECCAK_HASH,
      metadata: { source: 'git' },
    });
    const json = JSON.parse(JSON.stringify(p));
    expect(json.parentHash).toBe(KECCAK_HASH);
    expect(json.metadata.source).toBe('git');
  });
});
