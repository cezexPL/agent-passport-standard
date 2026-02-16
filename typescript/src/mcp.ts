// §17 MCP Security Profile — APS v1.1

export interface ToolAllowEntry {
  serverHash: string;
  toolName: string;
  version: string;
  dataClassificationMax: 'public' | 'internal' | 'confidential' | 'restricted';
}

export interface EgressPolicy {
  defaultDeny: boolean;
  allowedDomains: string[];
  allowedIPs: string[];
}

export interface AuditEntry {
  timestamp: string;
  action: string;
  toolName: string;
  serverHash: string;
  outcome: 'allow' | 'deny' | 'error';
  detail?: string;
}

export interface MCPSecurityProfile {
  specVersion: string;
  agentDid: string;
  toolAllow: ToolAllowEntry[];
  egressPolicy: EgressPolicy;
  auditLog: AuditEntry[];
  profileHash: string;
  createdAt: string;
}

export interface MCPProfileOptions {
  agentDid: string;
  toolAllow: ToolAllowEntry[];
  egressPolicy: EgressPolicy;
  auditLog?: AuditEntry[];
}

export function createMCPProfile(opts: MCPProfileOptions): MCPSecurityProfile {
  return {
    specVersion: '1.1',
    agentDid: opts.agentDid,
    toolAllow: opts.toolAllow,
    egressPolicy: opts.egressPolicy,
    auditLog: opts.auditLog ?? [],
    profileHash: '',
    createdAt: new Date().toISOString(),
  };
}

const CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted'];

export function validateMCPProfile(profile: MCPSecurityProfile): string[] {
  const errors: string[] = [];
  if (!profile.agentDid || !profile.agentDid.startsWith('did:')) {
    errors.push('agentDid must be a valid DID');
  }
  if (!Array.isArray(profile.toolAllow)) {
    errors.push('toolAllow must be an array');
  } else {
    for (const entry of profile.toolAllow) {
      if (!entry.serverHash || !entry.toolName || !entry.version) {
        errors.push(`toolAllow entry missing required fields: ${JSON.stringify(entry)}`);
      }
      if (!CLASSIFICATIONS.includes(entry.dataClassificationMax)) {
        errors.push(`invalid dataClassificationMax: ${entry.dataClassificationMax}`);
      }
    }
  }
  if (!profile.egressPolicy || typeof profile.egressPolicy.defaultDeny !== 'boolean') {
    errors.push('egressPolicy.defaultDeny must be a boolean');
  }
  if (!Array.isArray(profile.egressPolicy?.allowedDomains)) {
    errors.push('egressPolicy.allowedDomains must be an array');
  }
  if (!Array.isArray(profile.egressPolicy?.allowedIPs)) {
    errors.push('egressPolicy.allowedIPs must be an array');
  }
  for (const entry of profile.auditLog) {
    if (!entry.timestamp || !entry.action || !entry.toolName) {
      errors.push(`auditLog entry missing required fields`);
    }
    if (!['allow', 'deny', 'error'].includes(entry.outcome)) {
      errors.push(`invalid audit outcome: ${entry.outcome}`);
    }
  }
  return errors;
}
