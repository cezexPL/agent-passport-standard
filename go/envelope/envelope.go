// Package envelope implements the Security Envelope artifact from the Agent Passport Standard v0.1.
package envelope

import (
	"encoding/json"
	"fmt"
	"time"

	"crypto/ed25519"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/validate"
)

// SecurityEnvelope declares execution constraints for an agent.
type SecurityEnvelope struct {
	Context           string       `json:"@context"`
	SpecVersion       string       `json:"spec_version"`
	Type              string       `json:"type"`
	AgentDID          string       `json:"agent_did"`
	AgentSnapshotHash string       `json:"agent_snapshot_hash"`
	Capabilities      Capabilities `json:"capabilities"`
	Sandbox           SandboxProfile `json:"sandbox"`
	Memory            MemoryBoundary `json:"memory"`
	Trust             TrustInfo    `json:"trust"`
	EnvelopeHash      string       `json:"envelope_hash"`
	Proof             *Proof       `json:"proof,omitempty"`
}

// Capabilities defines allowed/denied operations.
type Capabilities struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

// SandboxProfile specifies execution environment.
type SandboxProfile struct {
	Runtime    string     `json:"runtime"`
	Resources  Resources  `json:"resources"`
	Network    NetworkPolicy `json:"network"`
	Filesystem Filesystem `json:"filesystem"`
}

// Resources describes compute limits.
type Resources struct {
	CPUCores       float64 `json:"cpu_cores"`
	MemoryMB       int     `json:"memory_mb"`
	DiskMB         int     `json:"disk_mb"`
	TimeoutSeconds int     `json:"timeout_seconds"`
	MaxPids        int     `json:"max_pids"`
}

// NetworkPolicy describes network access.
type NetworkPolicy struct {
	Policy        string   `json:"policy"`
	AllowedEgress []string `json:"allowed_egress,omitempty"`
	DNSResolution bool     `json:"dns_resolution"`
}

// Filesystem describes path access rules.
type Filesystem struct {
	WritablePaths []string `json:"writable_paths"`
	ReadonlyPaths []string `json:"readonly_paths"`
	DeniedPaths   []string `json:"denied_paths"`
}

// MemoryBoundary defines data isolation rules.
type MemoryBoundary struct {
	Isolation string      `json:"isolation"`
	Policy    string      `json:"policy"`
	Rules     MemoryRules `json:"rules"`
	Vault     Vault       `json:"vault"`
}

// MemoryRules defines what can be shared/copied.
type MemoryRules struct {
	DNACopyable       bool `json:"dna_copyable"`
	MemoryCopyable    bool `json:"memory_copyable"`
	ContextShared     bool `json:"context_shared"`
	LogsRetained      bool `json:"logs_retained"`
	LogsContentVisible bool `json:"logs_content_visible"`
}

// Vault describes persistent storage encryption.
type Vault struct {
	Type       string `json:"type"`
	Encryption string `json:"encryption"`
	KeyHolder  string `json:"key_holder"`
}

// TrustInfo holds trust tier and signals.
type TrustInfo struct {
	Tier              int     `json:"tier"`
	AttestationCount  int     `json:"attestation_count"`
	HighestAttestation string `json:"highest_attestation"`
	BenchmarkCoverage float64 `json:"benchmark_coverage"`
	AnomalyScore      float64 `json:"anomaly_score"`
}

// Proof is an Ed25519Signature2020 proof.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verification_method"`
	ProofPurpose       string `json:"proof_purpose"`
	ProofValue         string `json:"proof_value"`
}

// Config is used to create a new security envelope.
type Config struct {
	AgentDID          string
	AgentSnapshotHash string
	Capabilities      Capabilities
	Sandbox           SandboxProfile
	Memory            MemoryBoundary
	Trust             TrustInfo
}

// New creates a new SecurityEnvelope.
func New(cfg Config) (*SecurityEnvelope, error) {
	if cfg.AgentDID == "" {
		return nil, fmt.Errorf("agent_did is required")
	}

	e := &SecurityEnvelope{
		Context:           "https://agentpassport.org/v0.1",
		SpecVersion:       "0.1.0",
		Type:              "SecurityEnvelope",
		AgentDID:          cfg.AgentDID,
		AgentSnapshotHash: cfg.AgentSnapshotHash,
		Capabilities:      cfg.Capabilities,
		Sandbox:           cfg.Sandbox,
		Memory:            cfg.Memory,
		Trust:             cfg.Trust,
	}

	hash, err := e.Hash()
	if err != nil {
		return nil, err
	}
	e.EnvelopeHash = hash

	return e, nil
}

// Hash computes envelope_hash = keccak256(canonicalize(envelope - proof)).
func (e *SecurityEnvelope) Hash() (string, error) {
	return crypto.HashExcludingFields(e, "proof", "envelope_hash")
}

// Validate checks required fields and trust tier rules.
func (e *SecurityEnvelope) Validate() error {
	if e.AgentDID == "" {
		return fmt.Errorf("agent_did is required")
	}
	if e.Trust.Tier < 0 || e.Trust.Tier > 3 {
		return fmt.Errorf("trust tier must be 0-3, got %d", e.Trust.Tier)
	}

	// Trust tier rules from spec Section 3.5
	switch e.Trust.Tier {
	case 1:
		if e.Trust.AttestationCount < 1 {
			return fmt.Errorf("tier 1 requires >= 1 attestation, got %d", e.Trust.AttestationCount)
		}
	case 2:
		if e.Trust.AttestationCount < 3 {
			return fmt.Errorf("tier 2 requires >= 3 attestations, got %d", e.Trust.AttestationCount)
		}
		if e.Trust.BenchmarkCoverage < 0.8 {
			return fmt.Errorf("tier 2 requires >= 0.8 benchmark coverage, got %f", e.Trust.BenchmarkCoverage)
		}
	case 3:
		if e.Trust.AttestationCount < 10 {
			return fmt.Errorf("tier 3 requires >= 10 attestations, got %d", e.Trust.AttestationCount)
		}
		if e.Trust.BenchmarkCoverage < 0.95 {
			return fmt.Errorf("tier 3 requires >= 0.95 benchmark coverage, got %f", e.Trust.BenchmarkCoverage)
		}
	}

	validRuntimes := map[string]bool{"gvisor": true, "firecracker": true, "wasm": true, "none": true}
	if !validRuntimes[e.Sandbox.Runtime] {
		return fmt.Errorf("invalid runtime: %s", e.Sandbox.Runtime)
	}

	validPolicies := map[string]bool{"deny-all": true, "allow-list": true, "unrestricted": true}
	if !validPolicies[e.Sandbox.Network.Policy] {
		return fmt.Errorf("invalid network policy: %s", e.Sandbox.Network.Policy)
	}

	return nil
}

// Sign signs the envelope with the given Ed25519 private key.
func (e *SecurityEnvelope) Sign(privateKey ed25519.PrivateKey) error {
	hash, err := e.Hash()
	if err != nil {
		return err
	}
	e.EnvelopeHash = hash

	savedProof := e.Proof
	e.Proof = nil

	canonical, err := crypto.CanonicalizeJSON(e)
	if err != nil {
		e.Proof = savedProof
		return err
	}

	sig := crypto.Ed25519Sign(privateKey, canonical)
	now := time.Now().UTC().Format(time.RFC3339)

	e.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now,
		VerificationMethod: e.AgentDID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}
	return nil
}

// JSON returns the canonical JSON representation.
func (e *SecurityEnvelope) JSON() ([]byte, error) {
	return crypto.CanonicalizeJSON(e)
}

// ValidateSchema validates the envelope against the JSON schema.
func (e *SecurityEnvelope) ValidateSchema() error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return validate.ValidateEnvelope(data)
}

// FromJSON parses a SecurityEnvelope from JSON. Set validate to true (default) to run schema validation.
func FromJSON(data []byte, opts ...bool) (*SecurityEnvelope, error) {
	doValidate := true
	if len(opts) > 0 {
		doValidate = opts[0]
	}
	if doValidate {
		if err := validate.ValidateEnvelope(data); err != nil {
			return nil, fmt.Errorf("schema validation: %w", err)
		}
	}
	var e SecurityEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &e, nil
}
