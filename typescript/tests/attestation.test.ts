import { describe, it, expect } from 'vitest';
import { createAttestation, Attestation, AttestationRegistry } from '../src/attestation.js';
import { generateKeyPair } from '../src/crypto.js';

describe('Attestation', () => {
  it('should create and verify an attestation', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const att = await createAttestation('did:key:z6MkIssuer', 'did:key:z6MkSubject', 'SkillVerification', { skill: 'typescript' }, privateKey);
    expect(att.data.issuer).toBe('did:key:z6MkIssuer');
    expect(att.data.credentialSubject.id).toBe('did:key:z6MkSubject');
    expect(await att.verify(publicKey)).toBe(true);
  });

  it('should reject tampered attestation', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const att = await createAttestation('did:key:z6MkIssuer', 'did:key:z6MkSubject', 'SkillVerification', { skill: 'typescript' }, privateKey);
    att.data.credentialSubject.claims.skill = 'hacking';
    expect(await att.verify(publicKey)).toBe(false);
  });

  it('should reject expired attestation', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const expired = new Date(Date.now() - 3600000).toISOString();
    const att = await createAttestation('did:key:z6MkIssuer', 'did:key:z6MkSubject', 'SkillVerification', { skill: 'typescript' }, privateKey, expired);
    expect(await att.verify(publicKey)).toBe(false);
  });

  it('should reject wrong key', async () => {
    const { privateKey } = generateKeyPair();
    const { publicKey: otherPub } = generateKeyPair();
    const att = await createAttestation('did:key:z6MkIssuer', 'did:key:z6MkSubject', 'SkillVerification', { skill: 'typescript' }, privateKey);
    expect(await att.verify(otherPub)).toBe(false);
  });
});

describe('AttestationRegistry', () => {
  it('should verify from registry', async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const registry = new AttestationRegistry();
    registry.registerIssuer('did:key:z6MkIssuer', publicKey);

    expect(registry.isTrusted('did:key:z6MkIssuer')).toBe(true);
    expect(registry.isTrusted('did:key:z6MkUnknown')).toBe(false);

    const att = await createAttestation('did:key:z6MkIssuer', 'did:key:z6MkSubject', 'SkillVerification', { skill: 'ts' }, privateKey);
    expect(await registry.verifyFromRegistry(att)).toBe(true);
  });

  it('should throw for untrusted issuer', async () => {
    const { privateKey } = generateKeyPair();
    const registry = new AttestationRegistry();
    const att = await createAttestation('did:key:z6MkUntrusted', 'did:key:z6MkSubject', 'Test', {}, privateKey);
    await expect(registry.verifyFromRegistry(att)).rejects.toThrow('not trusted');
  });
});
