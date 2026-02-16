import { describe, it, expect } from 'vitest';
import { createMCPProfile, validateMCPProfile } from '../src/mcp.js';

describe('MCP Security Profile (§17)', () => {
  const validOpts = {
    agentDid: 'did:key:z6MkTest',
    toolAllow: [{
      serverHash: 'sha256:abc123',
      toolName: 'web_search',
      version: '1.0.0',
      dataClassificationMax: 'internal' as const,
    }],
    egressPolicy: {
      defaultDeny: true,
      allowedDomains: ['api.example.com'],
      allowedIPs: ['10.0.0.1'],
    },
  };

  it('creates a valid profile', () => {
    const profile = createMCPProfile(validOpts);
    expect(profile.specVersion).toBe('1.1');
    expect(profile.agentDid).toBe('did:key:z6MkTest');
    expect(profile.toolAllow).toHaveLength(1);
    expect(profile.auditLog).toEqual([]);
    expect(profile.createdAt).toBeTruthy();
  });

  it('validates a correct profile with no errors', () => {
    const profile = createMCPProfile(validOpts);
    expect(validateMCPProfile(profile)).toEqual([]);
  });

  it('reports errors for invalid agentDid', () => {
    const profile = createMCPProfile(validOpts);
    profile.agentDid = 'not-a-did';
    const errors = validateMCPProfile(profile);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain('agentDid');
  });

  it('reports errors for invalid dataClassificationMax', () => {
    const profile = createMCPProfile({ ...validOpts, toolAllow: [{ ...validOpts.toolAllow[0] }] });
    (profile.toolAllow[0] as any).dataClassificationMax = 'secret';
    const errors = validateMCPProfile(profile);
    expect(errors.some(e => e.includes('dataClassificationMax'))).toBe(true);
  });

  it('serializes to JSON and back', () => {
    const profile = createMCPProfile(validOpts);
    const json = JSON.stringify(profile);
    const parsed = JSON.parse(json);
    expect(parsed.specVersion).toBe('1.1');
    expect(parsed.toolAllow[0].toolName).toBe('web_search');
  });

  it('includes audit log entries', () => {
    const profile = createMCPProfile({
      ...validOpts,
      auditLog: [{
        timestamp: new Date().toISOString(),
        action: 'invoke',
        toolName: 'web_search',
        serverHash: 'sha256:abc',
        outcome: 'allow',
      }],
    });
    expect(profile.auditLog).toHaveLength(1);
    expect(validateMCPProfile(profile)).toEqual([]);
  });
});
