import { describe, it, expect } from 'vitest';
import { createRotation } from '../src/rotation.js';
import type { IdentityChain } from '../src/rotation.js';

describe('Key Rotation (§19)', () => {
  it('creates a rotation record', () => {
    const r = createRotation('did:key:z6MkOld', 'did:key:z6MkNew', 'key-compromise');
    expect(r.specVersion).toBe('1.1');
    expect(r.oldDid).toBe('did:key:z6MkOld');
    expect(r.newDid).toBe('did:key:z6MkNew');
    expect(r.reason).toBe('key-compromise');
    expect(r.rotatedAt).toBeTruthy();
  });

  it('throws if oldDid is not a DID', () => {
    expect(() => createRotation('not-did', 'did:key:z6MkNew', 'test')).toThrow('oldDid');
  });

  it('throws if newDid is not a DID', () => {
    expect(() => createRotation('did:key:z6MkOld', 'bad', 'test')).toThrow('newDid');
  });

  it('throws if old and new are the same', () => {
    expect(() => createRotation('did:key:z6MkSame', 'did:key:z6MkSame', 'test')).toThrow('differ');
  });

  it('builds an identity chain', () => {
    const chain: IdentityChain = [
      createRotation('did:key:z6Mk1', 'did:key:z6Mk2', 'scheduled'),
      createRotation('did:key:z6Mk2', 'did:key:z6Mk3', 'scheduled'),
    ];
    expect(chain).toHaveLength(2);
    expect(chain[0].newDid).toBe(chain[1].oldDid);
  });

  it('serializes to JSON', () => {
    const r = createRotation('did:key:z6MkA', 'did:key:z6MkB', 'upgrade');
    const parsed = JSON.parse(JSON.stringify(r));
    expect(parsed.reason).toBe('upgrade');
  });
});
