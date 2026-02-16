import { decryptPrivateKey, sign, toHex, fromHex } from '../crypto.js';
import { loadIdentity } from '../storage.js';

export async function apsSignWork(args: { data: string; passphrase: string }) {
  const identity = await loadIdentity();
  if (!identity) return { error: 'No identity found.' };

  let privateKey: Uint8Array;
  try {
    privateKey = decryptPrivateKey(identity.privateKey, args.passphrase);
  } catch {
    return { error: 'Invalid passphrase.' };
  }

  const dataBytes = new TextEncoder().encode(args.data);
  const signature = sign(dataBytes, privateKey);

  return {
    signature: toHex(signature),
    did: identity.did,
    timestamp: new Date().toISOString(),
    algorithm: 'Ed25519',
  };
}
