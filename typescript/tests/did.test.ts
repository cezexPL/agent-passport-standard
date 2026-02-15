import { describe, it, expect } from 'vitest';
import { resolveDIDKey, extractPublicKey } from '../src/did.js';
import { generateKeyPair } from '../src/crypto.js';
import { bytesToHex } from '@noble/hashes/utils';

// Minimal base58 encode for test
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let str = '';
  for (const byte of bytes) {
    if (byte !== 0) break;
    str += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    str += BASE58_ALPHABET[digits[i]];
  }
  return str;
}

describe('DID Resolution', () => {
  it('resolves did:key', () => {
    const { publicKey } = generateKeyPair();
    const multicodec = new Uint8Array([0xed, 0x01, ...publicKey]);
    const multibase = 'z' + base58Encode(multicodec);
    const did = `did:key:${multibase}`;

    const doc = resolveDIDKey(did);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod.length).toBe(1);

    const extracted = extractPublicKey(doc);
    expect(bytesToHex(extracted)).toBe(bytesToHex(publicKey));
  });

  it('rejects invalid did:key', () => {
    expect(() => resolveDIDKey('did:key:invalid')).toThrow();
  });
});
