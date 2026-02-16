// §19 Key Rotation — APS v1.1

export interface KeyRotation {
  specVersion: string;
  oldDid: string;
  newDid: string;
  reason: string;
  rotatedAt: string;
  proof?: string;
}

export type IdentityChain = KeyRotation[];

export function createRotation(oldDid: string, newDid: string, reason: string): KeyRotation {
  if (!oldDid.startsWith('did:')) throw new Error('oldDid must be a valid DID');
  if (!newDid.startsWith('did:')) throw new Error('newDid must be a valid DID');
  if (oldDid === newDid) throw new Error('oldDid and newDid must differ');
  return {
    specVersion: '1.1',
    oldDid,
    newDid,
    reason,
    rotatedAt: new Date().toISOString(),
  };
}
