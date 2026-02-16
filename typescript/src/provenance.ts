// §18 Provenance — APS v1.1

export interface Provenance {
  specVersion: string;
  artifactDid: string;
  creatorDid: string;
  hashChain: string[];
  parentHash: string | null;
  createdAt: string;
  metadata?: Record<string, unknown>;
}

export interface ProvenanceOptions {
  artifactDid: string;
  creatorDid: string;
  hashChain: string[];
  parentHash?: string | null;
  metadata?: Record<string, unknown>;
}

const HASH_PATTERN = /^(sha256|keccak256):[0-9a-f]{64}$/;

export function validateHashFormat(hash: string): boolean {
  return HASH_PATTERN.test(hash);
}

export function createProvenance(opts: ProvenanceOptions): Provenance {
  for (const h of opts.hashChain) {
    if (!validateHashFormat(h)) {
      throw new Error(`Invalid hash format: ${h}. Expected sha256:<hex64> or keccak256:<hex64>`);
    }
  }
  return {
    specVersion: '1.1',
    artifactDid: opts.artifactDid,
    creatorDid: opts.creatorDid,
    hashChain: opts.hashChain,
    parentHash: opts.parentHash ?? null,
    createdAt: new Date().toISOString(),
    metadata: opts.metadata,
  };
}
