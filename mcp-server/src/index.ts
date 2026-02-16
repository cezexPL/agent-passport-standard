#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { apsIdentityCreate, apsIdentityShow, apsIdentityDelete } from './tools/identity.js';
import { apsSignWork } from './tools/sign.js';
import { apsVerify } from './tools/verify.js';
import { apsExportPassport, apsImportPassport } from './tools/passport.js';
import { apsAttest } from './tools/attest.js';

const server = new McpServer({
  name: 'aps-identity-mcp',
  version: '1.0.0',
});

server.tool(
  'aps_identity_create',
  'Create a new Ed25519 cryptographic identity with a DID. Private key is encrypted with your passphrase.',
  { passphrase: z.string().min(1).describe('Passphrase to encrypt the private key') },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await apsIdentityCreate(args), null, 2) }] })
);

server.tool(
  'aps_identity_show',
  'Show current identity (DID, public key). Never exposes private key.',
  {},
  async () => ({ content: [{ type: 'text', text: JSON.stringify(await apsIdentityShow(), null, 2) }] })
);

server.tool(
  'aps_identity_delete',
  'Delete the current identity from ~/.aps/identity.json',
  {},
  async () => ({ content: [{ type: 'text', text: JSON.stringify(await apsIdentityDelete(), null, 2) }] })
);

server.tool(
  'aps_sign_work',
  'Sign data with your Ed25519 private key. Returns signature, DID, and timestamp.',
  {
    data: z.string().describe('Data to sign'),
    passphrase: z.string().describe('Passphrase to decrypt private key'),
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await apsSignWork(args), null, 2) }] })
);

server.tool(
  'aps_verify',
  'Verify an Ed25519 signature against a DID.',
  {
    data: z.string().describe('Original data that was signed'),
    signature: z.string().describe('Hex-encoded signature'),
    did: z.string().describe('DID of the signer (did:key:z6Mk...)'),
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await apsVerify(args), null, 2) }] })
);

server.tool(
  'aps_export_passport',
  'Export a signed Agent Passport bundle with DID, public key, skills, and attestations.',
  {
    passphrase: z.string().describe('Passphrase to sign the passport bundle'),
    skills: z.array(z.string()).optional().describe('List of skills to include'),
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await apsExportPassport(args), null, 2) }] })
);

server.tool(
  'aps_import_passport',
  'Import and verify a signed Agent Passport bundle.',
  {
    passport: z.string().describe('JSON string of the signed passport bundle'),
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await apsImportPassport(args), null, 2) }] })
);

server.tool(
  'aps_attest',
  'Create a W3C Verifiable Credential style attestation for another agent.',
  {
    subject_did: z.string().describe('DID of the agent being attested'),
    attestation_type: z.string().describe('Type of attestation (e.g., "code_review", "task_completion")'),
    evidence: z.string().describe('Evidence or description of the attestation'),
    passphrase: z.string().describe('Passphrase to sign the attestation'),
  },
  async (args) => ({ content: [{ type: 'text', text: JSON.stringify(await apsAttest(args), null, 2) }] })
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
