import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import bs58 from 'bs58';

// ed25519 needs sha512
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateKeypair(): KeyPair {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/** Create did:key from Ed25519 public key (multicodec 0xed 0x01 + base58btc) */
export function publicKeyToDid(publicKey: Uint8Array): string {
  const multicodec = new Uint8Array(2 + publicKey.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKey, 2);
  return `did:key:z${bs58.encode(multicodec)}`;
}

/** Extract public key bytes from did:key */
export function didToPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) throw new Error('Invalid did:key format');
  const decoded = bs58.decode(did.slice(8));
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error('Not an Ed25519 did:key');
  return decoded.slice(2);
}

export function sign(data: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed.sign(data, privateKey);
}

export function verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

export function encryptPrivateKey(privateKey: Uint8Array, passphrase: string): string {
  const salt = randomBytes(16);
  const key = Buffer.alloc(32);
  const passBytes = Buffer.from(passphrase, 'utf8');
  const h = sha512.create();
  h.update(salt);
  h.update(passBytes);
  h.digest().slice(0, 32).forEach((b, i) => key[i] = b);

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  const tag = cipher.getAuthTag();

  return JSON.stringify({
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    encrypted: encrypted.toString('hex'),
    tag: tag.toString('hex'),
  });
}

export function decryptPrivateKey(encryptedJson: string, passphrase: string): Uint8Array {
  const { salt, iv, encrypted, tag } = JSON.parse(encryptedJson);
  const saltBuf = Buffer.from(salt, 'hex');
  const key = Buffer.alloc(32);
  const passBytes = Buffer.from(passphrase, 'utf8');
  const h = sha512.create();
  h.update(saltBuf);
  h.update(passBytes);
  h.digest().slice(0, 32).forEach((b, i) => key[i] = b);

  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted, 'hex')), decipher.final()]);
  return new Uint8Array(decrypted);
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
