// Package passport implements the Agent Passport artifact from the Agent Passport Standard v0.1.
package passport

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/validate"
)

// AgentPassport is the top-level passport document.
type AgentPassport struct {
	Context      string                   `json:"@context"`
	SpecVersion  string                   `json:"spec_version"`
	Type         string                   `json:"type"`
	ID           string                   `json:"id"`
	Keys         Keys                     `json:"keys"`
	GenesisOwner GenesisOwner             `json:"genesis_owner"`
	CurrentOwner CurrentOwner             `json:"current_owner"`
	Snapshot     Snapshot                 `json:"snapshot"`
	Lineage      Lineage                  `json:"lineage"`
	Benchmarks   map[string]BenchmarkResult `json:"benchmarks,omitempty"`
	Attestations []Attestation            `json:"attestations,omitempty"`
	Anchoring    *Anchoring               `json:"anchoring,omitempty"`
	Proof        *Proof                   `json:"proof,omitempty"`
}

// Keys holds the agent's cryptographic keys.
type Keys struct {
	Signing    SigningKey   `json:"signing"`
	Encryption interface{} `json:"encryption"`
	EVM        *EVMKey     `json:"evm,omitempty"`
}

// SigningKey is an Ed25519 signing key.
type SigningKey struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// EVMKey is an Ethereum-compatible address.
type EVMKey struct {
	Address string `json:"address"`
}

// GenesisOwner is the immutable original creator.
type GenesisOwner struct {
	ID        string `json:"id"`
	BoundAt   string `json:"bound_at"`
	Immutable bool   `json:"immutable"`
}

// CurrentOwner is the current owner of the passport.
type CurrentOwner struct {
	ID            string  `json:"id"`
	TransferredAt *string `json:"transferred_at"`
}

// Snapshot is a versioned capture of agent state.
type Snapshot struct {
	Version   int      `json:"version"`
	Hash      string   `json:"hash"`
	PrevHash  *string  `json:"prev_hash"`
	CreatedAt string   `json:"created_at"`
	Skills    Skills   `json:"skills"`
	Soul      Soul     `json:"soul"`
	Policies  Policies `json:"policies"`
}

// Skills holds skill entries and frozen state.
type Skills struct {
	Entries []Skill `json:"entries"`
	Frozen  bool    `json:"frozen"`
}

// Skill describes one agent capability.
type Skill struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Capabilities []string `json:"capabilities"`
	Source       string   `json:"source,omitempty"`
	Hash         string   `json:"hash"`
}

// Soul describes personality and constraints.
type Soul struct {
	Personality string   `json:"personality"`
	WorkStyle   string   `json:"work_style"`
	Constraints []string `json:"constraints"`
	Hash        string   `json:"hash"`
	Frozen      bool     `json:"frozen"`
}

// Policies describes the agent's policy set.
type Policies struct {
	PolicySetHash string   `json:"policy_set_hash"`
	Summary       []string `json:"summary"`
}

// Lineage describes agent derivation.
type Lineage struct {
	Kind       string   `json:"kind"`
	Parents    []string `json:"parents"`
	Generation int      `json:"generation"`
}

// BenchmarkResult records a benchmark run.
type BenchmarkResult struct {
	Score     float64 `json:"score"`
	Passed    bool    `json:"passed"`
	SuiteHash string  `json:"suite_hash"`
	ProofHash string  `json:"proof_hash"`
	TestedAt  string  `json:"tested_at"`
}

// Attestation is a third-party credential.
type Attestation struct {
	Type           string  `json:"type"`
	Issuer         string  `json:"issuer"`
	CredentialHash string  `json:"credential_hash"`
	IssuedAt       string  `json:"issued_at"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
}

// Anchoring records on-chain anchoring.
type Anchoring struct {
	Provider string `json:"provider"`
	Contract string `json:"contract"`
	TxHash   string `json:"tx_hash"`
	Block    int    `json:"block"`
	Verified bool   `json:"verified"`
}

// Proof is an Ed25519Signature2020 proof.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// Config is used to create a new passport.
type Config struct {
	ID          string
	PublicKey   string
	OwnerDID    string
	Skills      []Skill
	Soul        Soul
	Policies    Policies
	Lineage     Lineage
	EVMAddress  string
}

// New creates a new AgentPassport from the given config.
func New(cfg Config) (*AgentPassport, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if cfg.PublicKey == "" {
		return nil, fmt.Errorf("public_key is required")
	}
	if cfg.OwnerDID == "" {
		return nil, fmt.Errorf("owner_did is required")
	}

	now := time.Now().UTC().Format(time.RFC3339)

	p := &AgentPassport{
		Context:     "https://agentpassport.org/v0.1",
		SpecVersion: "0.1.0",
		Type:        "AgentPassport",
		ID:          cfg.ID,
		Keys: Keys{
			Signing: SigningKey{
				Algorithm: "Ed25519",
				PublicKey: cfg.PublicKey,
			},
			Encryption: nil,
		},
		GenesisOwner: GenesisOwner{
			ID:        cfg.OwnerDID,
			BoundAt:   now,
			Immutable: true,
		},
		CurrentOwner: CurrentOwner{
			ID:            cfg.OwnerDID,
			TransferredAt: nil,
		},
		Snapshot: Snapshot{
			Version:   1,
			PrevHash:  nil,
			CreatedAt: now,
			Skills: Skills{
				Entries: cfg.Skills,
				Frozen:  false,
			},
			Soul:     cfg.Soul,
			Policies: cfg.Policies,
		},
		Lineage: cfg.Lineage,
	}

	if cfg.EVMAddress != "" {
		p.Keys.EVM = &EVMKey{Address: cfg.EVMAddress}
	}

	// Compute snapshot hash
	snapshotContent := map[string]interface{}{
		"skills":   p.Snapshot.Skills,
		"soul":     p.Snapshot.Soul,
		"policies": p.Snapshot.Policies,
	}
	hash, err := crypto.SnapshotHash(snapshotContent)
	if err != nil {
		return nil, fmt.Errorf("compute snapshot hash: %w", err)
	}
	p.Snapshot.Hash = hash

	return p, nil
}

// UpdateSnapshot creates a new snapshot version with updated skills/soul/policies.
// Enforces: monotonic version increment, prev_hash chain, frozen immutability.
func (p *AgentPassport) UpdateSnapshot(cfg SnapshotUpdate) error {
	// Frozen check: if skills are frozen, they cannot be modified
	if p.Snapshot.Skills.Frozen && cfg.Skills != nil {
		return fmt.Errorf("cannot update skills: frozen at version %d", p.Snapshot.Version)
	}
	if p.Snapshot.Soul.Frozen && cfg.Soul != nil {
		return fmt.Errorf("cannot update soul: frozen at version %d", p.Snapshot.Version)
	}

	// Save current hash as prev_hash
	prevHash := p.Snapshot.Hash

	// Increment version (monotonic)
	newVersion := p.Snapshot.Version + 1

	// Apply updates
	if cfg.Skills != nil {
		p.Snapshot.Skills.Entries = cfg.Skills
	}
	if cfg.Soul != nil {
		p.Snapshot.Soul = *cfg.Soul
	}
	if cfg.Policies != nil {
		p.Snapshot.Policies = *cfg.Policies
	}
	if cfg.FreezeSkills {
		p.Snapshot.Skills.Frozen = true
	}
	if cfg.FreezeSoul {
		p.Snapshot.Soul.Frozen = true
	}

	// Compute new snapshot hash
	snapshotContent := map[string]interface{}{
		"skills":   p.Snapshot.Skills,
		"soul":     p.Snapshot.Soul,
		"policies": p.Snapshot.Policies,
	}
	hash, err := crypto.SnapshotHash(snapshotContent)
	if err != nil {
		return fmt.Errorf("compute snapshot hash: %w", err)
	}

	p.Snapshot.Version = newVersion
	p.Snapshot.PrevHash = &prevHash
	p.Snapshot.Hash = hash
	p.Snapshot.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	// Invalidate existing proof (passport changed, must re-sign)
	p.Proof = nil

	return nil
}

// ValidateSnapshotChain checks that snapshot version and prev_hash form a valid chain.
// prevSnapshots should be ordered by version (ascending). Current passport snapshot is validated last.
func ValidateSnapshotChain(current *AgentPassport, prevSnapshots []Snapshot) error {
	if current.Snapshot.Version < 1 {
		return fmt.Errorf("snapshot version must be >= 1, got %d", current.Snapshot.Version)
	}

	expectedVersion := 1
	var lastHash *string

	for _, snap := range prevSnapshots {
		if snap.Version != expectedVersion {
			return fmt.Errorf("expected version %d, got %d", expectedVersion, snap.Version)
		}
		if expectedVersion == 1 && snap.PrevHash != nil {
			return fmt.Errorf("version 1 must have nil prev_hash")
		}
		if expectedVersion > 1 {
			if snap.PrevHash == nil {
				return fmt.Errorf("version %d must have prev_hash", snap.Version)
			}
			if lastHash != nil && *snap.PrevHash != *lastHash {
				return fmt.Errorf("version %d prev_hash mismatch: expected %s, got %s", snap.Version, *lastHash, *snap.PrevHash)
			}
		}
		h := snap.Hash
		lastHash = &h
		expectedVersion++
	}

	// Validate current snapshot
	if current.Snapshot.Version != expectedVersion {
		return fmt.Errorf("current snapshot version mismatch: expected %d, got %d", expectedVersion, current.Snapshot.Version)
	}
	if expectedVersion > 1 && current.Snapshot.PrevHash == nil {
		return fmt.Errorf("current snapshot must have prev_hash for version %d", current.Snapshot.Version)
	}
	if lastHash != nil && current.Snapshot.PrevHash != nil && *current.Snapshot.PrevHash != *lastHash {
		return fmt.Errorf("current snapshot prev_hash mismatch")
	}

	return nil
}

// SnapshotUpdate holds fields to update in a snapshot.
type SnapshotUpdate struct {
	Skills       []Skill   // nil = no change
	Soul         *Soul     // nil = no change
	Policies     *Policies // nil = no change
	FreezeSkills bool
	FreezeSoul   bool
}

// Hash computes the keccak256 hash of the passport excluding the proof field.
func (p *AgentPassport) Hash() (string, error) {
	return crypto.HashExcludingFields(p, "proof")
}

// Sign signs the passport with the given Ed25519 private key.
func (p *AgentPassport) Sign(privateKey ed25519.PrivateKey) error {
	// Remove existing proof for hashing
	savedProof := p.Proof
	p.Proof = nil

	canonical, err := crypto.CanonicalizeJSON(p)
	if err != nil {
		p.Proof = savedProof
		return fmt.Errorf("canonicalize: %w", err)
	}

	sig := crypto.Ed25519Sign(privateKey, canonical)
	now := time.Now().UTC().Format(time.RFC3339)

	p.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now,
		VerificationMethod: p.ID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}
	return nil
}

// Verify verifies the Ed25519 proof on the passport.
func (p *AgentPassport) Verify(publicKey ed25519.PublicKey) (bool, error) {
	if p.Proof == nil {
		return false, fmt.Errorf("no proof present")
	}

	proof := p.Proof
	p.Proof = nil
	defer func() { p.Proof = proof }()

	canonical, err := crypto.CanonicalizeJSON(p)
	if err != nil {
		return false, fmt.Errorf("canonicalize: %w", err)
	}

	return crypto.Ed25519Verify(publicKey, canonical, proof.ProofValue)
}

// JSON returns the canonical JSON representation.
func (p *AgentPassport) JSON() ([]byte, error) {
	return crypto.CanonicalizeJSON(p)
}

// Validate validates the passport against the JSON schema.
func (p *AgentPassport) Validate() error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return validate.ValidatePassport(data)
}

// FromJSON parses an AgentPassport from JSON. Set validate to true to run schema validation.
func FromJSON(data []byte, opts ...bool) (*AgentPassport, error) {
	doValidate := true
	if len(opts) > 0 {
		doValidate = opts[0]
	}
	if doValidate {
		if err := validate.ValidatePassport(data); err != nil {
			return nil, fmt.Errorf("schema validation: %w", err)
		}
	}
	var p AgentPassport
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &p, nil
}
