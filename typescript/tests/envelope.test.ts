import { describe, it, expect } from 'vitest';
import { SecurityEnvelope } from '../src/envelope.js';
import { generateKeyPair } from '../src/crypto.js';
import type { EnvelopeConfig } from '../src/types.js';

function makeEnvelopeConfig(overrides?: Partial<EnvelopeConfig>): EnvelopeConfig {
  return {
    agentDID: 'did:key:z6MkAgent',
    agentSnapshotHash: '0xaaa',
    capabilities: { allowed: ['code_read', 'code_write'], denied: ['network_egress'] },
    sandbox: {
      runtime: 'gvisor',
      resources: { cpu_cores: 1, memory_mb: 1024, disk_mb: 2048, timeout_seconds: 600, max_pids: 64 },
      network: { policy: 'deny-all', allowed_egress: [], dns_resolution: false },
      filesystem: { writable_paths: ['/workspace'], readonly_paths: ['/usr'], denied_paths: ['/etc/shadow'] },
    },
    memory: {
      isolation: 'strict',
      policy: 'private-by-design',
      rules: { dna_copyable: true, memory_copyable: false, context_shared: false, logs_retained: true, logs_content_visible: false },
      vault: { type: 'platform-managed', encryption: 'aes-256-gcm', key_holder: 'agent_owner' },
    },
    trust: { tier: 2, attestation_count: 5, highest_attestation: 'ReliabilityGold', benchmark_coverage: 0.8, anomaly_score: 0.02 },
    ...overrides,
  };
}

describe('SecurityEnvelope', () => {
  it('validate trust tier rules (tier 0-3)', () => {
    // Tier 0 - always valid
    const e0 = SecurityEnvelope.create(makeEnvelopeConfig({ trust: { tier: 0, attestation_count: 0, highest_attestation: '', benchmark_coverage: 0, anomaly_score: 0 } }));
    expect(() => e0.validate()).not.toThrow();

    // Tier 1 - needs >= 1 attestation
    const e1bad = SecurityEnvelope.create(makeEnvelopeConfig({ trust: { tier: 1, attestation_count: 0, highest_attestation: '', benchmark_coverage: 0, anomaly_score: 0 } }));
    expect(() => e1bad.validate()).toThrow('tier 1 requires >= 1 attestation');

    const e1ok = SecurityEnvelope.create(makeEnvelopeConfig({ trust: { tier: 1, attestation_count: 1, highest_attestation: '', benchmark_coverage: 0, anomaly_score: 0 } }));
    expect(() => e1ok.validate()).not.toThrow();

    // Tier 2 - needs >= 3 attestations + 0.8 coverage
    const e2 = SecurityEnvelope.create(makeEnvelopeConfig());
    expect(() => e2.validate()).not.toThrow();

    const e2bad = SecurityEnvelope.create(makeEnvelopeConfig({ trust: { tier: 2, attestation_count: 2, highest_attestation: '', benchmark_coverage: 0.8, anomaly_score: 0 } }));
    expect(() => e2bad.validate()).toThrow('tier 2 requires >= 3 attestations');

    // Tier 3
    const e3bad = SecurityEnvelope.create(makeEnvelopeConfig({ trust: { tier: 3, attestation_count: 5, highest_attestation: '', benchmark_coverage: 0.95, anomaly_score: 0 } }));
    expect(() => e3bad.validate()).toThrow('tier 3 requires >= 10 attestations');
  });

  it('reject invalid runtime', () => {
    const cfg = makeEnvelopeConfig();
    cfg.sandbox.runtime = 'docker';
    const e = SecurityEnvelope.create(cfg);
    expect(() => e.validate()).toThrow('invalid runtime: docker');
  });

  it('reject invalid network policy', () => {
    const cfg = makeEnvelopeConfig();
    cfg.sandbox.network.policy = 'allow-all';
    const e = SecurityEnvelope.create(cfg);
    expect(() => e.validate()).toThrow('invalid network policy: allow-all');
  });

  it('create → sign → hash', async () => {
    const { privateKey } = generateKeyPair();
    const e = SecurityEnvelope.create(makeEnvelopeConfig());
    expect(e.data.envelope_hash).toBeTruthy();

    await e.sign(privateKey);
    expect(e.data.proof).toBeTruthy();
  });

  it('fromJson/toJson roundtrip', () => {
    const e = SecurityEnvelope.create(makeEnvelopeConfig());
    const json = e.toJson();
    const restored = SecurityEnvelope.fromJson(json, false);
    expect(restored.hash()).toBe(e.hash());
  });
});
