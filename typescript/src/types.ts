// All TypeScript interfaces/types for the Agent Passport Standard v0.1

// v1.1 re-exports (§17-§21)
export type { MCPSecurityProfile, ToolAllowEntry, EgressPolicy, AuditEntry, MCPProfileOptions } from './mcp.js';
export type { Provenance, ProvenanceOptions } from './provenance.js';
export type { KeyRotation, IdentityChain } from './rotation.js';
export type { ExecutionAttestation, ExecutionAttestationOptions } from './execution.js';
export { TrustLevel } from './execution.js';
export type { ReputationScore, ReputationAttestation } from './sybil.js';

export interface SigningKey {
  algorithm: string;
  public_key: string;
}

export interface EVMKey {
  address: string;
}

export interface Keys {
  signing: SigningKey;
  encryption: unknown;
  evm?: EVMKey;
}

export interface GenesisOwner {
  id: string;
  bound_at: string;
  immutable: boolean;
}

export interface CurrentOwner {
  id: string;
  transferred_at?: string | null;
}

export interface Skill {
  name: string;
  version: string;
  description: string;
  capabilities: string[];
  source?: string;
  hash: string;
}

export interface Skills {
  entries: Skill[];
  frozen: boolean;
}

export interface Soul {
  personality: string;
  work_style: string;
  constraints: string[];
  hash: string;
  frozen: boolean;
}

export interface Policies {
  policy_set_hash: string;
  summary: string[];
}

export interface Snapshot {
  version: number;
  hash: string;
  prev_hash?: string | null;
  created_at: string;
  skills: Skills;
  soul: Soul;
  policies: Policies;
}

export interface Lineage {
  kind: string;
  parents: string[];
  generation: number;
}

export interface BenchmarkResult {
  score: number;
  passed: boolean;
  suite_hash: string;
  proof_hash: string;
  tested_at: string;
}

export interface Attestation {
  type: string;
  issuer: string;
  credential_hash: string;
  issued_at: string;
  expires_at?: string | null;
}

export interface Anchoring {
  provider: string;
  contract: string;
  tx_hash: string;
  block: number;
  verified: boolean;
}

export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}

// Passport
export interface AgentPassportData {
  '@context': string;
  spec_version: string;
  type: string;
  id: string;
  keys: Keys;
  genesis_owner: GenesisOwner;
  current_owner: CurrentOwner;
  snapshot: Snapshot;
  lineage: Lineage;
  benchmarks?: Record<string, BenchmarkResult>;
  attestations?: Attestation[];
  anchoring?: Anchoring | null;
  proof?: Proof | null;
}

export interface PassportConfig {
  id: string;
  publicKey: string;
  ownerDID: string;
  skills: Skill[];
  soul: Soul;
  policies: Policies;
  lineage: Lineage;
  evmAddress?: string;
}

// Receipt
export interface AgentSnapshotRef {
  version: number;
  hash: string;
}

export interface VerifyResult {
  status: string;
  score?: number;
  stages?: Record<string, string>;
}

export interface PayoutAmount {
  value: number;
  unit: string;
  distribution?: Record<string, number>;
}

export interface ReceiptEvent {
  type: string;
  timestamp: string;
  payload_hash: string;
  signature: string;
  evidence?: Record<string, string>;
  result?: VerifyResult;
  amount?: PayoutAmount;
}

export interface BatchAnchoring {
  provider: string;
  tx_hash: string;
  verified: boolean;
}

export interface BatchProof {
  batch_root: string;
  leaf_index: number;
  proof: string[];
  batch_anchoring?: BatchAnchoring;
}

export interface WorkReceiptData {
  '@context': string;
  spec_version: string;
  type: string;
  receipt_id: string;
  job_id: string;
  agent_did: string;
  client_did: string;
  platform_did?: string;
  agent_snapshot: AgentSnapshotRef;
  events: ReceiptEvent[];
  batch_proof?: BatchProof | null;
  receipt_hash: string;
  proof?: Proof | null;
}

export interface ReceiptConfig {
  receiptId: string;
  jobId: string;
  agentDID: string;
  clientDID: string;
  platformDID?: string;
  agentSnapshot: AgentSnapshotRef;
}

// Envelope
export interface Capabilities {
  allowed: string[];
  denied: string[];
}

export interface Resources {
  cpu_cores: number;
  memory_mb: number;
  disk_mb: number;
  timeout_seconds: number;
  max_pids: number;
}

export interface NetworkPolicy {
  policy: string;
  allowed_egress?: string[];
  dns_resolution: boolean;
}

export interface Filesystem {
  writable_paths: string[];
  readonly_paths: string[];
  denied_paths: string[];
}

export interface SandboxProfile {
  runtime: string;
  resources: Resources;
  network: NetworkPolicy;
  filesystem: Filesystem;
}

export interface MemoryRules {
  dna_copyable: boolean;
  memory_copyable: boolean;
  context_shared: boolean;
  logs_retained: boolean;
  logs_content_visible: boolean;
}

export interface Vault {
  type: string;
  encryption: string;
  key_holder: string;
}

export interface MemoryBoundary {
  isolation: string;
  policy: string;
  rules: MemoryRules;
  vault: Vault;
}

export interface TrustInfo {
  tier: number;
  attestation_count: number;
  highest_attestation: string;
  benchmark_coverage: number;
  anomaly_score: number;
}

export interface SecurityEnvelopeData {
  '@context': string;
  spec_version: string;
  type: string;
  agent_did: string;
  agent_snapshot_hash: string;
  capabilities: Capabilities;
  sandbox: SandboxProfile;
  memory: MemoryBoundary;
  trust: TrustInfo;
  envelope_hash: string;
  proof?: Proof | null;
}

export interface EnvelopeConfig {
  agentDID: string;
  agentSnapshotHash: string;
  capabilities: Capabilities;
  sandbox: SandboxProfile;
  memory: MemoryBoundary;
  trust: TrustInfo;
}

// Anchor
export interface AnchorReceipt {
  tx_hash: string;
  block: number;
  timestamp: string;
  provider: string;
}

export interface AnchorVerification {
  exists: boolean;
  tx_hash?: string;
  block?: number;
  timestamp?: string;
}

export interface ProviderInfo {
  name: string;
  chain_id: string;
  type: string;
}

export interface AnchorMetadata {
  artifact_type: string;
  description: string;
}

// Compat
export interface AgentsMD {
  raw: string;
  instructions: string[];
  constraints: string[];
  tools: string[];
}
