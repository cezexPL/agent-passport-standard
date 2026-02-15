# @APS/sdk — Agent Passport Standard TypeScript SDK

TypeScript implementation of the [Agent Passport Standard](https://agentpassport.org) v0.1.

## Quick Start

```bash
npm install @APS/sdk
```

```typescript
import { AgentPassport, generateKeyPair, SecurityEnvelope, WorkReceipt } from '@APS/sdk';

// Generate keys
const { publicKey, privateKey } = generateKeyPair();

// Create a passport
const passport = await AgentPassport.create({
  id: 'did:key:z6Mk...',
  publicKey: Buffer.from(publicKey).toString('hex'),
  ownerDID: 'did:key:z6MkOwner...',
  skills: [{ name: 'typescript', version: '1.0.0', description: 'TS dev', capabilities: ['code_write'], hash: '0x...' }],
  soul: { personality: 'focused', work_style: 'test-first', constraints: [], hash: '0x...', frozen: false },
  policies: { policy_set_hash: '0x...', summary: ['can_bid'] },
  lineage: { kind: 'original', parents: [], generation: 0 },
});

// Sign and verify
await passport.sign(privateKey);
const valid = await passport.verify(publicKey);
```

## Compatibility

- Node.js 20+
- Deno (via npm specifiers)

## License

MIT
