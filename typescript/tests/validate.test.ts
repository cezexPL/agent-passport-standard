import { describe, it, expect } from 'vitest';
import { validatePassport, validateDNA, ValidationError } from '../src/validate.js';

const HEX64 = '0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
const DID = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';

const validPassport = () => ({
  '@context': 'https://agentpassport.org/v0.1',
  spec_version: '0.1.0',
  type: 'AgentPassport',
  id: DID,
  keys: { signing: { algorithm: 'Ed25519', public_key: 'z6MkpTHR' } },
  genesis_owner: { id: DID, bound_at: '2025-01-01T00:00:00Z', immutable: true },
  current_owner: { id: DID },
  snapshot: {
    version: 1,
    hash: HEX64,
    prev_hash: null,
    created_at: '2025-01-01T00:00:00Z',
    skills: {
      entries: [{ name: 'go', version: '1.0', description: 'Go', capabilities: ['code'], hash: HEX64 }],
      frozen: false,
    },
    soul: { personality: 'f', work_style: 't', constraints: [], hash: HEX64, frozen: false },
    policies: { policy_set_hash: HEX64, summary: ['can_bid'] },
  },
  lineage: { kind: 'single', parents: [], generation: 0 },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2025-01-01T00:00:00Z',
    verification_method: `${DID}#keys-1`,
    proof_purpose: 'assertionMethod',
    proof_value: 'zSIG',
  },
});

const validDna = () => ({
  '@context': 'https://agentpassport.org/v0.2/dna',
  type: 'AgentDNA',
  agent_id: DID,
  version: 1,
  skills: [],
  soul: { personality: 'f', work_style: 't', constraints: [] },
  policies: { policy_set_hash: HEX64, summary: ['x'] },
  dna_hash: HEX64,
  frozen: false,
});

describe('validatePassport', () => {
  it('accepts valid passport', () => {
    expect(() => validatePassport(validPassport())).not.toThrow();
  });

  it('rejects missing @context', () => {
    const d = validPassport();
    delete (d as any)['@context'];
    expect(() => validatePassport(d)).toThrow(ValidationError);
  });

  it('rejects missing id', () => {
    const d = validPassport();
    delete (d as any).id;
    expect(() => validatePassport(d)).toThrow(ValidationError);
  });

  it('rejects wrong type for spec_version', () => {
    const d = validPassport();
    (d as any).spec_version = 123;
    expect(() => validatePassport(d)).toThrow(ValidationError);
  });

  it('rejects extra fields', () => {
    const d = { ...validPassport(), extra: 'hello' };
    expect(() => validatePassport(d)).toThrow(ValidationError);
  });

  it('rejects skills.entries wrong type', () => {
    const d = validPassport();
    (d as any).snapshot.skills.entries = 'not-array';
    expect(() => validatePassport(d)).toThrow(ValidationError);
  });
});

describe('validateDNA', () => {
  it('accepts valid DNA', () => {
    expect(() => validateDNA(validDna())).not.toThrow();
  });

  it('rejects missing dna_hash', () => {
    const d = validDna();
    delete (d as any).dna_hash;
    expect(() => validateDNA(d)).toThrow(ValidationError);
  });
});
