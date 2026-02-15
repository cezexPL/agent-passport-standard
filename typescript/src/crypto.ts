import { keccak_256 } from '@noble/hashes/sha3';
import { sha512 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import * as ed from '@noble/ed25519';

// @noble/ed25519 v2 requires sha512 to be set manually
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

/**
 * Canonicalize a value to deterministic JSON with sorted keys (RFC 8785-like).
 */
export function canonicalizeJson(value: unknown): string {
  return serializeValue(value);
}

function serializeValue(v: unknown): string {
  if (v === null) return 'null';
  if (v === undefined) return 'null';

  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') return JSON.stringify(v);
  if (t === 'string') return JSON.stringify(v);

  if (Array.isArray(v)) {
    return '[' + v.map(serializeValue).join(',') + ']';
  }

  if (t === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const val = obj[k];
      if (val === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + serializeValue(val));
    }
    return '{' + parts.join(',') + '}';
  }

  return JSON.stringify(v);
}

/**
 * Compute keccak-256 hash, returning "0x" + hex string.
 */
export function keccak256(data: Uint8Array): string {
  const hash = keccak_256(data);
  return '0x' + bytesToHex(hash);
}

/**
 * Compute keccak-256 hash, returning raw 32 bytes.
 */
export function keccak256Bytes(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/**
 * Canonicalize payload and compute keccak256.
 */
export function snapshotHash(payload: unknown): string {
  const canonical = canonicalizeJson(payload);
  return keccak256(new TextEncoder().encode(canonical));
}

/**
 * Hash an object excluding specified top-level keys.
 */
export function hashExcludingFields(v: unknown, ...exclude: string[]): string {
  // Convert to plain object via JSON round-trip
  const obj = JSON.parse(JSON.stringify(v)) as Record<string, unknown>;
  for (const key of exclude) {
    delete obj[key];
  }
  const canonical = canonicalizeJson(obj);
  return keccak256(new TextEncoder().encode(canonical));
}

/**
 * Sign data with Ed25519 private key, returning hex signature.
 */
export async function ed25519Sign(privateKey: Uint8Array, data: Uint8Array): Promise<string> {
  const seed = privateKey.length > 32 ? privateKey.slice(0, 32) : privateKey;
  const sig = ed.sign(data, seed);
  return bytesToHex(sig);
}

/**
 * Verify Ed25519 signature (hex) against public key and data.
 */
export async function ed25519Verify(publicKey: Uint8Array, data: Uint8Array, signatureHex: string): Promise<boolean> {
  const sig = hexToBytes(signatureHex);
  return ed.verify(sig, data, publicKey);
}

/**
 * Generate Ed25519 key pair. Returns { publicKey, privateKey } as Uint8Arrays.
 */
export function generateKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

// --- Merkle Tree ---

export class MerkleTree {
  readonly leaves: string[];
  readonly layers: string[][];

  constructor(inputLeaves: string[]) {
    if (inputLeaves.length === 0) {
      this.leaves = [];
      this.layers = [];
      return;
    }

    const normalized = [...inputLeaves];
    // Pad to power of 2
    while ((normalized.length & (normalized.length - 1)) !== 0) {
      normalized.push(normalized[normalized.length - 1]);
    }

    this.leaves = normalized;
    this.layers = [normalized];

    let current = normalized;
    while (current.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(hashPair(current[i], current[i + 1]));
      }
      this.layers.push(next);
      current = next;
    }
  }

  root(): string {
    if (this.layers.length === 0) return '';
    const top = this.layers[this.layers.length - 1];
    return top.length === 0 ? '' : top[0];
  }

  proof(index: number): string[] {
    if (index < 0 || index >= this.leaves.length) return [];

    const proof: string[] = [];
    let idx = index;
    for (let i = 0; i < this.layers.length - 1; i++) {
      const layer = this.layers[i];
      if (idx % 2 === 0) {
        if (idx + 1 < layer.length) proof.push(layer[idx + 1]);
      } else {
        proof.push(layer[idx - 1]);
      }
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  static verifyProof(leaf: string, root: string, proof: string[], index: number): boolean {
    let current = leaf;
    let idx = index;
    for (const sibling of proof) {
      if (idx % 2 === 0) {
        current = hashPair(current, sibling);
      } else {
        current = hashPair(sibling, current);
      }
      idx = Math.floor(idx / 2);
    }
    return timingSafeEqual(current, root);
  }
}

function hashPair(a: string, b: string): string {
  let aBytes = hexToBytes(a);
  let bBytes = hexToBytes(b);

  // Sorted concat: min || max by hex
  const aHex = bytesToHex(aBytes);
  const bHex = bytesToHex(bBytes);
  if (aHex > bHex) {
    [aBytes, bBytes] = [bBytes, aBytes];
  }

  const combined = new Uint8Array(aBytes.length + bBytes.length);
  combined.set(aBytes, 0);
  combined.set(bBytes, aBytes.length);

  return keccak256(combined);
}

// --- Timing-Safe Comparison ---

/**
 * Constant-time string comparison to prevent timing attacks.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// --- Input Validation ---

const DID_RE = /^did:key:z6Mk[A-Za-z0-9]+$/;
const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const SIG_RE = /^[0-9a-fA-F]{128}$/;

export function validateDid(s: string): void {
  if (!s) throw new Error('DID must not be empty');
  if (!DID_RE.test(s)) throw new Error(`invalid DID format: ${s}`);
}

export function validateHash(s: string): void {
  if (!s) throw new Error('hash must not be empty');
  if (!HASH_RE.test(s)) throw new Error(`invalid hash format: ${s}`);
}

export function validateSignature(s: string): void {
  if (!s) throw new Error('signature must not be empty');
  if (!SIG_RE.test(s)) throw new Error(`invalid signature format: ${s}`);
}

export function validateTimestamp(s: string): void {
  if (!s) throw new Error('timestamp must not be empty');
  const d = new Date(s);
  if (isNaN(d.getTime())) throw new Error(`invalid timestamp: ${s}`);
}

export function validateVersion(v: number): void {
  if (!Number.isInteger(v) || v < 1) throw new Error(`version must be positive integer, got ${v}`);
}

export function validateTrustTier(t: number): void {
  if (!Number.isInteger(t) || t < 0 || t > 3) throw new Error(`trust tier must be 0-3, got ${t}`);
}

export function validateAttestationCount(c: number): void {
  if (!Number.isInteger(c) || c < 0) throw new Error(`attestation count must be non-negative, got ${c}`);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
