import { decryptPrivateKey, sign, verify, toHex, fromHex, didToPublicKey } from '../crypto.js';
import { loadIdentity } from '../storage.js';

export async function apsExportPassport(args: { passphrase: string; skills?: string[] }) {
  const identity = await loadIdentity();
  if (!identity) return { error: 'No identity found.' };

  let privateKey: Uint8Array;
  try {
    privateKey = decryptPrivateKey(identity.privateKey, args.passphrase);
  } catch {
    return { error: 'Invalid passphrase.' };
  }

  const bundle = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-passport-standard.org/v1'],
    type: 'AgentPassport',
    did: identity.did,
    publicKey: identity.publicKey,
    skills: args.skills || identity.skills || [],
    attestations: identity.attestations || [],
    createdAt: identity.createdAt,
    exportedAt: new Date().toISOString(),
  };

  const bundleBytes = new TextEncoder().encode(JSON.stringify(bundle));
  const signature = sign(bundleBytes, privateKey);

  return {
    passport: bundle,
    signature: toHex(signature),
    algorithm: 'Ed25519',
  };
}

export async function apsImportPassport(args: { passport: string }) {
  try {
    const parsed = JSON.parse(args.passport);
    const { passport, signature } = parsed;
    if (!passport || !signature) return { error: 'Invalid passport bundle format.' };

    const publicKey = didToPublicKey(passport.did);
    const bundleBytes = new TextEncoder().encode(JSON.stringify(passport));
    const valid = verify(bundleBytes, fromHex(signature), publicKey);

    return {
      valid,
      did: passport.did,
      publicKey: passport.publicKey,
      skills: passport.skills || [],
      attestationCount: (passport.attestations || []).length,
      createdAt: passport.createdAt,
      exportedAt: passport.exportedAt,
    };
  } catch (e: any) {
    return { valid: false, error: e.message };
  }
}
