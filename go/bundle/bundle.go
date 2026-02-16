// Package bundle implements portable passport bundles for cross-platform agent identity transfer.
package bundle

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cezexPL/agent-passport-standard/go/anchor"
	"github.com/cezexPL/agent-passport-standard/go/attestation"
	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/passport"
	"github.com/cezexPL/agent-passport-standard/go/receipt"
)

// AgentPassportBundle is a self-contained, portable package for cross-platform transfer.
type AgentPassportBundle struct {
	Context      string                      `json:"@context"`
	Type         string                      `json:"type"`
	Version      string                      `json:"version"`
	ExportedAt   string                      `json:"exported_at"`
	ExportedFrom string                      `json:"exported_from"`
	Passport     *passport.AgentPassport     `json:"passport"`
	WorkReceipts []receipt.WorkReceipt       `json:"work_receipts,omitempty"`
	Attestations []attestation.Attestation   `json:"attestations,omitempty"`
	Reputation   *ReputationSummary          `json:"reputation_summary,omitempty"`
	AnchorProofs []anchor.AnchorReceipt      `json:"anchoring_proofs,omitempty"`
	Proof        *BundleProof                `json:"proof,omitempty"`
}

// ReputationSummary holds aggregated reputation metrics.
type ReputationSummary struct {
	AgentID         string             `json:"agent_id"`
	Platform        string             `json:"platform"`
	Period          Period             `json:"period"`
	JobsCompleted   int                `json:"jobs_completed"`
	JobsVerified    int                `json:"jobs_verified"`
	AvgQuality      float64            `json:"avg_quality_score"`
	AvgTimeliness   float64            `json:"avg_timeliness_score"`
	TrustTier       int                `json:"trust_tier"`
	BenchmarkScores map[string]float64 `json:"benchmark_scores,omitempty"`
	ComputedAt      string             `json:"computed_at"`
}

// Period defines a time range.
type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// BundleProof is the Ed25519 proof over the bundle.
type BundleProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// VerificationReport summarizes verification of all bundle components.
type VerificationReport struct {
	BundleValid       bool     `json:"bundle_valid"`
	PassportValid     bool     `json:"passport_valid"`
	ReceiptsValid     []bool   `json:"receipts_valid,omitempty"`
	AttestationsValid []bool   `json:"attestations_valid,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}

// BundleOption configures optional bundle fields.
type BundleOption func(*AgentPassportBundle)

// WithReceipts adds work receipts to the bundle.
func WithReceipts(receipts []receipt.WorkReceipt) BundleOption {
	return func(b *AgentPassportBundle) { b.WorkReceipts = receipts }
}

// WithAttestations adds attestations to the bundle.
func WithAttestations(atts []attestation.Attestation) BundleOption {
	return func(b *AgentPassportBundle) { b.Attestations = atts }
}

// WithReputation adds a reputation summary to the bundle.
func WithReputation(rep ReputationSummary) BundleOption {
	return func(b *AgentPassportBundle) { b.Reputation = &rep }
}

// WithAnchorProofs adds anchor proofs to the bundle.
func WithAnchorProofs(proofs []anchor.AnchorReceipt) BundleOption {
	return func(b *AgentPassportBundle) { b.AnchorProofs = proofs }
}

// WithPlatformDID sets the exported_from field.
func WithPlatformDID(did string) BundleOption {
	return func(b *AgentPassportBundle) { b.ExportedFrom = did }
}

// NewBundle creates a new AgentPassportBundle.
func NewBundle(p *passport.AgentPassport, opts ...BundleOption) *AgentPassportBundle {
	b := &AgentPassportBundle{
		Context:    "https://agentpassport.org/v0.2/bundle",
		Type:       "AgentPassportBundle",
		Version:    "1.0.0",
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Passport:   p,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Sign signs the entire bundle with the given Ed25519 private key.
func (b *AgentPassportBundle) Sign(privateKey ed25519.PrivateKey) error {
	b.Proof = nil

	canonical, err := crypto.CanonicalizeJSON(b)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	sig := crypto.Ed25519Sign(privateKey, canonical)
	now := time.Now().UTC().Format(time.RFC3339)

	b.Proof = &BundleProof{
		Type:               "Ed25519Signature2020",
		Created:            now,
		VerificationMethod: b.Passport.ID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}
	return nil
}

// Verify verifies the bundle's Ed25519 signature.
func (b *AgentPassportBundle) Verify(publicKey ed25519.PublicKey) (bool, error) {
	if b.Proof == nil {
		return false, fmt.Errorf("no proof present")
	}

	proof := b.Proof
	b.Proof = nil
	defer func() { b.Proof = proof }()

	canonical, err := crypto.CanonicalizeJSON(b)
	if err != nil {
		return false, fmt.Errorf("canonicalize: %w", err)
	}

	return crypto.Ed25519Verify(publicKey, canonical, proof.ProofValue)
}

// VerifyAll verifies the bundle signature, passport signature, and all receipt/attestation signatures.
func (b *AgentPassportBundle) VerifyAll(publicKey ed25519.PublicKey) (*VerificationReport, error) {
	report := &VerificationReport{}

	if b.Passport == nil {
		report.Errors = append(report.Errors, "no passport in bundle")
		return report, nil
	}

	pubKey := publicKey

	// Verify bundle signature
	valid, err := b.Verify(pubKey)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("bundle verify: %v", err))
	} else {
		report.BundleValid = valid
	}

	// Verify passport signature
	valid, err = b.Passport.Verify(pubKey)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("passport verify: %v", err))
	} else {
		report.PassportValid = valid
	}

	// Verify receipts
	for i, r := range b.WorkReceipts {
		r := r // copy for pointer safety
		valid, err := r.Verify(pubKey)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("receipt[%d] verify: %v", i, err))
			report.ReceiptsValid = append(report.ReceiptsValid, false)
		} else {
			report.ReceiptsValid = append(report.ReceiptsValid, valid)
		}
	}

	// Verify attestations
	for i, a := range b.Attestations {
		a := a
		valid, err := attestation.VerifyAttestation(&a, pubKey)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("attestation[%d] verify: %v", i, err))
			report.AttestationsValid = append(report.AttestationsValid, false)
		} else {
			report.AttestationsValid = append(report.AttestationsValid, valid)
		}
	}

	return report, nil
}

// Hash computes keccak256 of the canonical bundle excluding the proof field.
func (b *AgentPassportBundle) Hash() (string, error) {
	return crypto.HashExcludingFields(b, "proof")
}

// JSON returns the canonical JSON representation of the bundle.
func (b *AgentPassportBundle) JSON() ([]byte, error) {
	return crypto.CanonicalizeJSON(b)
}

// FromJSON parses an AgentPassportBundle from JSON.
func FromJSON(data []byte) (*AgentPassportBundle, error) {
	var b AgentPassportBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &b, nil
}
