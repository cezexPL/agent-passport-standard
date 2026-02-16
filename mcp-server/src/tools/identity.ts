import { generateKeypair, publicKeyToDid, encryptPrivateKey, toHex } from '../crypto.js';
import { loadIdentity, saveIdentity, deleteIdentity } from '../storage.js';

export async function apsIdentityCreate(args: { passphrase: string }) {
  const existing = await loadIdentity();
  if (existing) {
    return { error: 'Identity already exists. Delete it first with aps_identity_delete.' };
  }

  const { publicKey, privateKey } = generateKeypair();
  const did = publicKeyToDid(publicKey);
  const encryptedKey = encryptPrivateKey(privateKey, args.passphrase);

  await saveIdentity({
    did,
    publicKey: toHex(publicKey),
    privateKey: encryptedKey,
    createdAt: new Date().toISOString(),
    attestations: [],
    skills: [],
  });

  return { did, publicKey: toHex(publicKey), createdAt: new Date().toISOString() };
}

export async function apsIdentityShow() {
  const identity = await loadIdentity();
  if (!identity) return { error: 'No identity found. Create one with aps_identity_create.' };
  return {
    did: identity.did,
    publicKey: identity.publicKey,
    createdAt: identity.createdAt,
    skills: identity.skills || [],
    attestationCount: (identity.attestations || []).length,
  };
}

export async function apsIdentityDelete() {
  const deleted = await deleteIdentity();
  return deleted
    ? { success: true, message: 'Identity deleted.' }
    : { error: 'No identity found to delete.' };
}
