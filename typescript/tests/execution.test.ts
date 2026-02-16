import { describe, it, expect } from 'vitest';
import { createExecutionAttestation, TrustLevel } from '../src/execution.js';

describe('Execution Attestation (§20)', () => {
  it('creates an attestation with TrustLevel enum', () => {
    const att = createExecutionAttestation({
      agentDid: 'did:key:z6MkAgent',
      taskHash: 'sha256:' + 'c'.repeat(64),
      trustLevel: TrustLevel.High,
      attestedBy: 'did:key:z6MkVerifier',
    });
    expect(att.specVersion).toBe('1.1');
    expect(att.trustLevel).toBe(3);
    expect(att.attestedAt).toBeTruthy();
  });

  it('supports all trust levels', () => {
    expect(TrustLevel.None).toBe(0);
    expect(TrustLevel.Low).toBe(1);
    expect(TrustLevel.Medium).toBe(2);
    expect(TrustLevel.High).toBe(3);
  });

  it('throws on invalid trust level', () => {
    expect(() => createExecutionAttestation({
      agentDid: 'did:key:z6MkAgent',
      taskHash: 'hash',
      trustLevel: 5 as any,
      attestedBy: 'did:key:z6MkV',
    })).toThrow('trustLevel');
  });

  it('includes optional evidence', () => {
    const att = createExecutionAttestation({
      agentDid: 'did:key:z6MkAgent',
      taskHash: 'hash',
      trustLevel: TrustLevel.Medium,
      attestedBy: 'did:key:z6MkV',
      evidence: { benchmarkScore: 95 },
    });
    expect(att.evidence?.benchmarkScore).toBe(95);
  });

  it('serializes to JSON', () => {
    const att = createExecutionAttestation({
      agentDid: 'did:key:z6MkAgent',
      taskHash: 'h',
      trustLevel: TrustLevel.Low,
      attestedBy: 'did:key:z6MkV',
    });
    const parsed = JSON.parse(JSON.stringify(att));
    expect(parsed.trustLevel).toBe(1);
  });
});
