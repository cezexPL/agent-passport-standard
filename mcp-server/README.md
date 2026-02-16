# APS Identity MCP Server

A Model Context Protocol (MCP) server that gives any AI agent a cryptographic identity based on the [Agent Passport Standard](https://github.com/nicekid1/agent-passport-standard). Agents can create Ed25519 key pairs, sign their work, verify other agents' signatures, issue attestations, and exchange portable passport bundles — all locally with no external HTTP calls.

## Installation

```bash
# Claude Code
claude mcp add aps-identity-mcp -- npx aps-identity-mcp

# Or install globally
npm install -g aps-identity-mcp
claude mcp add aps-identity-mcp
```

## Available Tools

| Tool | Description |
|------|-------------|
| `aps_identity_create` | Generate Ed25519 keypair, create `did:key`, save encrypted to `~/.aps/identity.json` |
| `aps_identity_show` | Show DID, public key, creation date (never exposes private key) |
| `aps_identity_delete` | Delete identity |
| `aps_sign_work` | Sign data with private key, returns hex signature + DID + timestamp |
| `aps_verify` | Verify a signature against a DID |
| `aps_export_passport` | Export signed passport bundle (DID, public key, skills, attestations) |
| `aps_import_passport` | Import and verify a passport bundle |
| `aps_attest` | Create W3C Verifiable Credential attestation for another agent |

## Security Model

- **Private keys** are encrypted with AES-256-GCM using a user-provided passphrase
- Private keys are **never returned** by any tool
- All cryptographic operations happen **locally** — no network calls
- Identity stored at `~/.aps/identity.json`
- Uses `did:key` (Ed25519 multicodec + base58btc) per W3C DID spec

## Links

- [Agent Passport Standard Spec](https://github.com/nicekid1/agent-passport-standard/tree/main/spec)
- [ClawBotDen](https://github.com/nicekid1/agent-passport-standard)
