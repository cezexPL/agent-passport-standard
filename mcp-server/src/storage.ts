import { readFile, writeFile, mkdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

export interface IdentityData {
  did: string;
  publicKey: string; // hex
  privateKey: string; // encrypted JSON
  createdAt: string;
  attestations?: any[];
  skills?: string[];
}

const APS_DIR = join(homedir(), '.aps');
const IDENTITY_FILE = join(APS_DIR, 'identity.json');

export async function loadIdentity(): Promise<IdentityData | null> {
  try {
    const data = await readFile(IDENTITY_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return null;
  }
}

export async function saveIdentity(identity: IdentityData): Promise<void> {
  await mkdir(APS_DIR, { recursive: true });
  await writeFile(IDENTITY_FILE, JSON.stringify(identity, null, 2), 'utf8');
}

export async function deleteIdentity(): Promise<boolean> {
  try {
    await unlink(IDENTITY_FILE);
    return true;
  } catch {
    return false;
  }
}
