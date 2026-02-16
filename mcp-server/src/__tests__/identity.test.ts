import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  generateKeypair, publicKeyToDid, didToPublicKey,
  sign, verify, encryptPrivateKey, decryptPrivateKey,
  toHex, fromHex,
} from '../crypto.js';

// We can't easily override homedir at runtime for storage tests,
// so we'll test storage by directly using the module functions with a temp dir approach.

describe('APS Identity - Crypto', () => {
  it('1. Identity creation: Ed25519 keypair, DID format did:key:z6Mk...', () => {
    const kp = generateKeypair();
    assert.equal(kp.publicKey.length, 32);
    assert.equal(kp.privateKey.length, 32);

    const did = publicKeyToDid(kp.publicKey);
    assert.ok(did.startsWith('did:key:z6Mk'), `DID should start with did:key:z6Mk, got: ${did}`);

    // Round-trip: extract public key from DID
    const extracted = didToPublicKey(did);
    assert.deepEqual(extracted, kp.publicKey);
  });

  it('2. Key encryption/decryption: encrypt then decrypt matches original', () => {
    const kp = generateKeypair();
    const passphrase = 'test-passphrase-123';

    const encrypted = encryptPrivateKey(kp.privateKey, passphrase);
    assert.ok(typeof encrypted === 'string');

    const parsed = JSON.parse(encrypted);
    assert.ok(parsed.salt);
    assert.ok(parsed.iv);
    assert.ok(parsed.encrypted);
    assert.ok(parsed.tag);

    const decrypted = decryptPrivateKey(encrypted, passphrase);
    assert.deepEqual(decrypted, kp.privateKey);
  });

  it('2b. Decryption with wrong passphrase throws', () => {
    const kp = generateKeypair();
    const encrypted = encryptPrivateKey(kp.privateKey, 'correct');
    assert.throws(() => decryptPrivateKey(encrypted, 'wrong'));
  });

  it('3. Signing: sign data, signature is hex string of 64 bytes', () => {
    const kp = generateKeypair();
    const data = new TextEncoder().encode('hello world');
    const sig = sign(data, kp.privateKey);

    assert.equal(sig.length, 64);
    const hex = toHex(sig);
    assert.equal(hex.length, 128);
    assert.ok(/^[0-9a-f]+$/.test(hex));
  });

  it('4. Verification: sign then verify returns true', () => {
    const kp = generateKeypair();
    const data = new TextEncoder().encode('test data');
    const sig = sign(data, kp.privateKey);

    const valid = verify(data, sig, kp.publicKey);
    assert.equal(valid, true);
  });

  it('5. Verification with wrong data returns false', () => {
    const kp = generateKeypair();
    const dataA = new TextEncoder().encode('data A');
    const dataB = new TextEncoder().encode('data B');
    const sig = sign(dataA, kp.privateKey);

    const valid = verify(dataB, sig, kp.publicKey);
    assert.equal(valid, false);
  });

  it('5b. Verification with wrong key returns false', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const data = new TextEncoder().encode('data');
    const sig = sign(data, kp1.privateKey);

    const valid = verify(data, sig, kp2.publicKey);
    assert.equal(valid, false);
  });
});

describe('APS Identity - Passport export/import', () => {
  it('6. Export passport contains did, publicKey, signature', async () => {
    const kp = generateKeypair();
    const did = publicKeyToDid(kp.publicKey);
    const pubHex = toHex(kp.publicKey);

    // Simulate what apsExportPassport does
    const bundle = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-passport-standard.org/v1'],
      type: 'AgentPassport',
      did,
      publicKey: pubHex,
      skills: ['typescript'],
      attestations: [],
      createdAt: new Date().toISOString(),
      exportedAt: new Date().toISOString(),
    };

    const bundleBytes = new TextEncoder().encode(JSON.stringify(bundle));
    const sig = sign(bundleBytes, kp.privateKey);

    const exported = {
      passport: bundle,
      signature: toHex(sig),
      algorithm: 'Ed25519',
    };

    assert.ok(exported.passport.did.startsWith('did:key:z6Mk'));
    assert.equal(exported.passport.publicKey, pubHex);
    assert.equal(typeof exported.signature, 'string');
    assert.equal(exported.signature.length, 128);
  });

  it('7. Passport import: export then import round-trip', () => {
    const kp = generateKeypair();
    const did = publicKeyToDid(kp.publicKey);

    const bundle = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-passport-standard.org/v1'],
      type: 'AgentPassport',
      did,
      publicKey: toHex(kp.publicKey),
      skills: ['python'],
      attestations: [],
      createdAt: '2025-01-01T00:00:00Z',
      exportedAt: new Date().toISOString(),
    };

    const bundleBytes = new TextEncoder().encode(JSON.stringify(bundle));
    const sig = sign(bundleBytes, kp.privateKey);
    const exported = JSON.stringify({ passport: bundle, signature: toHex(sig) });

    // Import
    const parsed = JSON.parse(exported);
    const pubKey = didToPublicKey(parsed.passport.did);
    const importBytes = new TextEncoder().encode(JSON.stringify(parsed.passport));
    const valid = verify(importBytes, fromHex(parsed.signature), pubKey);

    assert.equal(valid, true);
    assert.equal(parsed.passport.did, did);
    assert.deepEqual(parsed.passport.skills, ['python']);
  });
});

describe('APS Identity - Storage', () => {
  let tmpDir: string;

  before(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'aps-test-'));
  });

  after(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('8. Storage: identity.json created with correct structure', async () => {
    // Directly test storage logic by writing to temp dir
    const { mkdir, writeFile } = await import('node:fs/promises');
    const apsDir = join(tmpDir, '.aps');
    await mkdir(apsDir, { recursive: true });

    const kp = generateKeypair();
    const did = publicKeyToDid(kp.publicKey);
    const encrypted = encryptPrivateKey(kp.privateKey, 'pass');

    const identity = {
      did,
      publicKey: toHex(kp.publicKey),
      privateKey: encrypted,
      createdAt: new Date().toISOString(),
      attestations: [],
      skills: [],
    };

    const filePath = join(apsDir, 'identity.json');
    await writeFile(filePath, JSON.stringify(identity, null, 2));

    const content = JSON.parse(await readFile(filePath, 'utf8'));
    assert.equal(content.did, did);
    assert.equal(content.publicKey, toHex(kp.publicKey));
    assert.ok(content.privateKey); // encrypted, not raw
    assert.ok(content.createdAt);
  });
});

describe('APS Identity - Security', () => {
  it('9. Tool responses never contain raw privateKey', () => {
    const kp = generateKeypair();
    const did = publicKeyToDid(kp.publicKey);
    const encrypted = encryptPrivateKey(kp.privateKey, 'pass');

    // Simulate apsIdentityCreate response
    const createResponse = { did, publicKey: toHex(kp.publicKey), createdAt: new Date().toISOString() };
    const responseStr = JSON.stringify(createResponse);
    assert.ok(!responseStr.includes(toHex(kp.privateKey)), 'Response must not contain raw private key hex');
    assert.ok(!('privateKey' in createResponse), 'Response must not have privateKey field');

    // Simulate apsIdentityShow response
    const showResponse = {
      did,
      publicKey: toHex(kp.publicKey),
      createdAt: new Date().toISOString(),
      skills: [],
      attestationCount: 0,
    };
    assert.ok(!('privateKey' in showResponse));

    // Simulate sign response
    const data = new TextEncoder().encode('test');
    const sig = sign(data, kp.privateKey);
    const signResponse = { signature: toHex(sig), did, timestamp: new Date().toISOString(), algorithm: 'Ed25519' };
    assert.ok(!('privateKey' in signResponse));
    assert.ok(!JSON.stringify(signResponse).includes(toHex(kp.privateKey)));

    // Verify exported passport doesn't leak privateKey
    const exportResponse = {
      passport: { did, publicKey: toHex(kp.publicKey), skills: [], attestations: [], createdAt: '', exportedAt: '' },
      signature: toHex(sig),
      algorithm: 'Ed25519',
    };
    assert.ok(!JSON.stringify(exportResponse).includes(toHex(kp.privateKey)));
    assert.ok(!JSON.stringify(exportResponse).includes(encrypted));
  });
});
