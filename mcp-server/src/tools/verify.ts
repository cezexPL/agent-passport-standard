import { didToPublicKey, verify, fromHex } from '../crypto.js';

export async function apsVerify(args: { data: string; signature: string; did: string }) {
  try {
    const publicKey = didToPublicKey(args.did);
    const dataBytes = new TextEncoder().encode(args.data);
    const sigBytes = fromHex(args.signature);
    const valid = verify(dataBytes, sigBytes, publicKey);

    return {
      valid,
      did: args.did,
      timestamp: new Date().toISOString(),
    };
  } catch (e: any) {
    return { valid: false, error: e.message, did: args.did, timestamp: new Date().toISOString() };
  }
}
