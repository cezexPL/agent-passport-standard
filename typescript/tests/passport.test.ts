import { describe, it, expect } from 'vitest';
import { AgentPassport } from '../src/passport.js';
import { generateKeyPair, snapshotHash } from '../src/crypto.js';
import type { PassportConfig } from '../src/types.js';

function makeConfig(publicKey: string): PassportConfig {
  return {
    id: 'did:key:z6MkTest',
    publicKey,
    ownerDID: 'did:key:z6MkOwner',
    skills: [
      { name: 'go-developer', version: '1.0.0', description: 'Go backend', capabilities: ['code_write'], hash: '0xabc' },
    ],
    soul: { personality: 'focused', work_style: 'test-first', constraints: [], hash: '0xdef', frozen: false },
    policies: { policy_set_hash: '0x123', summary: ['can_bid'] },
    lineage: { kind: 'original', parents: [], generation: 0 },
  };
}

describe('AgentPassport', () => {
  it('create → sign → verify → hash matches', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const { bytesToHex } = await import('@noble/hashes/utils');
    const cfg = makeConfig(bytesToHex(publicKey));

    const passport = await AgentPassport.create(cfg);
    expect(passport.data.snapshot.version).toBe(1);
    expect(passport.data.snapshot.hash).toBeTruthy();

    const hashBefore = passport.hash();
    await passport.sign(privateKey);
    expect(passport.data.proof).toBeTruthy();

    const valid = await passport.verify(publicKey);
    expect(valid).toBe(true);

    // Hash should be consistent (excluding proof)
    const hashAfter = passport.hash();
    expect(hashAfter).toBe(hashBefore);
  });

  it('frozen skills enforcement', async () => {
    const { publicKey } = generateKeyPair();
    const { bytesToHex } = await import('@noble/hashes/utils');
    const cfg = makeConfig(bytesToHex(publicKey));

    const passport = await AgentPassport.create(cfg);
    passport.data.snapshot.skills.frozen = true;

    expect(() =>
      passport.addSkill({ name: 'new-skill', version: '1.0.0', description: 'test', capabilities: [], hash: '0x1' })
    ).toThrow('skills are frozen');
  });

  it('snapshot hash chain (version 1→2)', async () => {
    const { publicKey } = generateKeyPair();
    const { bytesToHex } = await import('@noble/hashes/utils');
    const cfg = makeConfig(bytesToHex(publicKey));

    const passport = await AgentPassport.create(cfg);
    const v1Hash = passport.data.snapshot.hash;
    expect(passport.data.snapshot.prev_hash).toBeNull();

    passport.newSnapshot();
    expect(passport.data.snapshot.version).toBe(2);
    expect(passport.data.snapshot.prev_hash).toBe(v1Hash);
  });

  it('fromJson/toJson roundtrip', async () => {
    const { publicKey } = generateKeyPair();
    const { bytesToHex } = await import('@noble/hashes/utils');
    const cfg = makeConfig(bytesToHex(publicKey));

    const passport = await AgentPassport.create(cfg);
    const json = passport.toJson();
    const restored = AgentPassport.fromJson(json);
    expect(restored.data.id).toBe(passport.data.id);
    expect(restored.hash()).toBe(passport.hash());
  });
});
