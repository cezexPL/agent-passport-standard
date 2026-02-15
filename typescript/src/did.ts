import { hexToBytes } from './crypto.js';

export interface DIDDocument {
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  raw?: Record<string, unknown>;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyBytes?: string;
  publicKeyBase58?: string;
}

// Base58 decode (minimal implementation for did:key)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base58 character: ${char}`);
    let carry = idx;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading zeros
  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

/**
 * Resolve a did:key (Ed25519, z6Mk prefix).
 */
export function resolveDIDKey(did: string): DIDDocument {
  if (!did.startsWith('did:key:z6Mk')) {
    throw new Error(`unsupported did:key format: ${did}`);
  }

  const multibaseValue = did.split(':')[2];
  // Remove 'z' prefix (base58btc)
  const rawBytes = base58Decode(multibaseValue.slice(1));

  if (rawBytes.length < 34 || rawBytes[0] !== 0xed || rawBytes[1] !== 0x01) {
    throw new Error('invalid Ed25519 multicodec prefix');
  }

  const pubKeyBytes = rawBytes.slice(2);
  const bytesHex = Array.from(pubKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  const vm: VerificationMethod = {
    id: did + '#key-1',
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase: multibaseValue,
    publicKeyBytes: bytesHex,
  };

  return {
    id: did,
    verificationMethod: [vm],
    authentication: [did + '#key-1'],
  };
}

/**
 * Resolve a did:web by fetching did.json.
 */
export async function resolveDIDWeb(did: string): Promise<DIDDocument> {
  if (!did.startsWith('did:web:')) {
    throw new Error(`not a did:web: ${did}`);
  }

  const parts = did.split(':').slice(2);
  const domain = parts[0].replace(/%3A/g, ':');
  const pathParts = parts.slice(1);

  const url = pathParts.length > 0
    ? `https://${domain}/${pathParts.join('/')}/did.json`
    : `https://${domain}/.well-known/did.json`;

  const resp = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!resp.ok) throw new Error(`failed to fetch ${url}: ${resp.status}`);
  const raw = await resp.json() as Record<string, unknown>;

  return {
    id: (raw.id as string) || did,
    verificationMethod: (raw.verificationMethod as VerificationMethod[]) || [],
    authentication: (raw.authentication as string[]) || [],
    raw,
  };
}

/**
 * Auto-dispatch DID resolution by method.
 */
export async function resolve(did: string): Promise<DIDDocument> {
  if (did.startsWith('did:key:')) return resolveDIDKey(did);
  if (did.startsWith('did:web:')) return resolveDIDWeb(did);
  throw new Error(`unsupported DID method: ${did}`);
}

/**
 * Extract the first Ed25519 public key bytes from a DID document.
 */
export function extractPublicKey(doc: DIDDocument): Uint8Array {
  for (const vm of doc.verificationMethod) {
    if (vm.publicKeyBytes) {
      return hexToBytes(vm.publicKeyBytes);
    }
    if (vm.publicKeyMultibase) {
      const raw = base58Decode(vm.publicKeyMultibase.slice(1));
      if (raw.length >= 34 && raw[0] === 0xed && raw[1] === 0x01) {
        return raw.slice(2);
      }
      return raw;
    }
    if (vm.publicKeyBase58) {
      return base58Decode(vm.publicKeyBase58);
    }
  }
  throw new Error('no Ed25519 public key found in DID document');
}
