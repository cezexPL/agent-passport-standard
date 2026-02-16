import { decryptPrivateKey, sign, toHex } from '../crypto.js';
import { loadIdentity, saveIdentity } from '../storage.js';
import { randomUUID } from 'node:crypto';

export async function apsAttest(args: {
  subject_did: string;
  attestation_type: string;
  evidence: string;
  passphrase: string;
}) {
  const identity = await loadIdentity();
  if (!identity) return { error: 'No identity found.' };

  let privateKey: Uint8Array;
  try {
    privateKey = decryptPrivateKey(identity.privateKey, args.passphrase);
  } catch {
    return { error: 'Invalid passphrase.' };
  }

  const credential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://agent-passport-standard.org/v1',
    ],
    type: ['VerifiableCredential', 'AgentAttestation'],
    id: `urn:uuid:${randomUUID()}`,
    issuer: identity.did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: args.subject_did,
      type: args.attestation_type,
      evidence: args.evidence,
    },
  };

  const credBytes = new TextEncoder().encode(JSON.stringify(credential));
  const signature = sign(credBytes, privateKey);

  const signedAttestation = {
    credential,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: `${identity.did}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: toHex(signature),
    },
  };

  // Store attestation
  if (!identity.attestations) identity.attestations = [];
  identity.attestations.push(signedAttestation);
  await saveIdentity(identity);

  return signedAttestation;
}
