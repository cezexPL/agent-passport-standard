// §20 Execution Attestation — APS v1.1

export enum TrustLevel {
  None = 0,
  Low = 1,
  Medium = 2,
  High = 3,
}

export interface ExecutionAttestation {
  specVersion: string;
  agentDid: string;
  taskHash: string;
  trustLevel: TrustLevel;
  attestedBy: string;
  attestedAt: string;
  evidence?: Record<string, unknown>;
}

export interface ExecutionAttestationOptions {
  agentDid: string;
  taskHash: string;
  trustLevel: TrustLevel;
  attestedBy: string;
  evidence?: Record<string, unknown>;
}

export function createExecutionAttestation(opts: ExecutionAttestationOptions): ExecutionAttestation {
  if (opts.trustLevel < 0 || opts.trustLevel > 3) {
    throw new Error('trustLevel must be 0-3');
  }
  return {
    specVersion: '1.1',
    agentDid: opts.agentDid,
    taskHash: opts.taskHash,
    trustLevel: opts.trustLevel,
    attestedBy: opts.attestedBy,
    attestedAt: new Date().toISOString(),
    evidence: opts.evidence,
  };
}
