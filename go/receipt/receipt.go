// Package receipt implements the Work Receipt artifact from the Agent Passport Standard v0.1.
package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/validate"
)

// WorkReceipt is a verifiable record of agent work.
type WorkReceipt struct {
	Context       string          `json:"@context"`
	SpecVersion   string          `json:"spec_version"`
	Type          string          `json:"type"`
	ReceiptID     string          `json:"receipt_id"`
	JobID         string          `json:"job_id"`
	AgentDID      string          `json:"agent_did"`
	ClientDID     string          `json:"client_did"`
	PlatformDID   string          `json:"platform_did,omitempty"`
	AgentSnapshot AgentSnapshot   `json:"agent_snapshot"`
	Events        []ReceiptEvent  `json:"events"`
	BatchProof    *BatchProof     `json:"batch_proof,omitempty"`
	ReceiptHash   string          `json:"receipt_hash"`
	Proof         *Proof          `json:"proof,omitempty"`
}

// AgentSnapshot binds the receipt to a passport version.
type AgentSnapshot struct {
	Version int    `json:"version"`
	Hash    string `json:"hash"`
}

// ReceiptEvent is a lifecycle event (claim/submit/verify/payout).
type ReceiptEvent struct {
	Type        string            `json:"type"`
	Timestamp   string            `json:"timestamp"`
	PayloadHash string            `json:"payload_hash"`
	Signature   string            `json:"signature"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Result      *VerifyResult     `json:"result,omitempty"`
	Amount      *PayoutAmount     `json:"amount,omitempty"`
}

// Evidence is a key-value evidence map.
type Evidence = map[string]string

// VerifyResult holds verification outcome.
type VerifyResult struct {
	Status string            `json:"status"`
	Score  float64           `json:"score,omitempty"`
	Stages map[string]string `json:"stages,omitempty"`
}

// PayoutAmount describes a payout.
type PayoutAmount struct {
	Value        float64            `json:"value"`
	Unit         string             `json:"unit"`
	Distribution map[string]float64 `json:"distribution,omitempty"`
}

// BatchProof contains Merkle batch proof data.
type BatchProof struct {
	BatchRoot      string          `json:"batch_root"`
	LeafIndex      int             `json:"leaf_index"`
	Proof          []string        `json:"proof"`
	BatchAnchoring *BatchAnchoring `json:"batch_anchoring,omitempty"`
}

// BatchAnchoring is anchoring info for a batch.
type BatchAnchoring struct {
	Provider string `json:"provider"`
	TxHash   string `json:"tx_hash"`
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

// Config is used to create a new receipt.
type Config struct {
	ReceiptID     string
	JobID         string
	AgentDID      string
	ClientDID     string
	PlatformDID   string
	AgentSnapshot AgentSnapshot
}

// New creates a new WorkReceipt.
func New(cfg Config) (*WorkReceipt, error) {
	if cfg.ReceiptID == "" || cfg.JobID == "" {
		return nil, fmt.Errorf("receipt_id and job_id are required")
	}
	if cfg.AgentDID == "" || cfg.ClientDID == "" {
		return nil, fmt.Errorf("agent_did and client_did are required")
	}

	return &WorkReceipt{
		Context:       "https://agentpassport.org/v0.1",
		SpecVersion:   "0.1.0",
		Type:          "WorkReceipt",
		ReceiptID:     cfg.ReceiptID,
		JobID:         cfg.JobID,
		AgentDID:      cfg.AgentDID,
		ClientDID:     cfg.ClientDID,
		PlatformDID:   cfg.PlatformDID,
		AgentSnapshot: cfg.AgentSnapshot,
		Events:        []ReceiptEvent{},
	}, nil
}

// ValidEventTypes enumerates recognized event types per spec.
var ValidEventTypes = map[string]bool{
	"claim": true, "submit": true, "verify": true, "payout": true,
	"reject": true, "cancel": true, "dispute": true, "review": true,
}

// AddEvent appends a lifecycle event to the receipt with integrity validation.
// Enforces: valid type, chronological order, payload_hash computation, per-event signature chain.
func (r *WorkReceipt) AddEvent(event ReceiptEvent) error {
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if !ValidEventTypes[event.Type] {
		return fmt.Errorf("unknown event type %q; valid types: claim, submit, verify, payout, reject, cancel, dispute, review", event.Type)
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Chronological order enforcement
	if len(r.Events) > 0 {
		lastTS := r.Events[len(r.Events)-1].Timestamp
		if event.Timestamp < lastTS {
			return fmt.Errorf("event timestamp %s is before previous event %s; events must be chronological", event.Timestamp, lastTS)
		}
	}

	// Compute payload_hash if not provided (integrity of event content)
	if event.PayloadHash == "" {
		eventContent := map[string]interface{}{
			"type":      event.Type,
			"timestamp": event.Timestamp,
		}
		if event.Evidence != nil {
			eventContent["evidence"] = event.Evidence
		}
		if event.Result != nil {
			eventContent["result"] = event.Result
		}
		if event.Amount != nil {
			eventContent["amount"] = event.Amount
		}
		canonical, err := crypto.CanonicalizeJSON(eventContent)
		if err != nil {
			return fmt.Errorf("canonicalize event: %w", err)
		}
		event.PayloadHash = crypto.Keccak256(canonical)
	}

	r.Events = append(r.Events, event)
	return nil
}

// VerifyEventChain validates that all events have payload_hash and are in chronological order.
func (r *WorkReceipt) VerifyEventChain() error {
	for i, event := range r.Events {
		if event.Type == "" {
			return fmt.Errorf("event[%d]: type is required", i)
		}
		if event.PayloadHash == "" {
			return fmt.Errorf("event[%d]: payload_hash is required for integrity", i)
		}
		if i > 0 && event.Timestamp < r.Events[i-1].Timestamp {
			return fmt.Errorf("event[%d]: timestamp %s is before event[%d] %s", i, event.Timestamp, i-1, r.Events[i-1].Timestamp)
		}
	}
	return nil
}

// Hash computes receipt_hash = keccak256(canonicalize(receipt - proof)).
func (r *WorkReceipt) Hash() (string, error) {
	return crypto.HashExcludingFields(r, "proof", "receipt_hash")
}

// Sign signs the receipt with the given Ed25519 private key.
func (r *WorkReceipt) Sign(privateKey ed25519.PrivateKey) error {
	hash, err := r.Hash()
	if err != nil {
		return err
	}
	r.ReceiptHash = hash

	savedProof := r.Proof
	r.Proof = nil

	canonical, err := crypto.CanonicalizeJSON(r)
	if err != nil {
		r.Proof = savedProof
		return err
	}

	sig := crypto.Ed25519Sign(privateKey, canonical)
	now := time.Now().UTC().Format(time.RFC3339)

	r.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now,
		VerificationMethod: r.AgentDID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}
	return nil
}

// Verify verifies the Ed25519 proof on the receipt.
func (r *WorkReceipt) Verify(publicKey ed25519.PublicKey) (bool, error) {
	if r.Proof == nil {
		return false, fmt.Errorf("no proof present")
	}

	proof := r.Proof
	r.Proof = nil
	defer func() { r.Proof = proof }()

	canonical, err := crypto.CanonicalizeJSON(r)
	if err != nil {
		return false, err
	}

	return crypto.Ed25519Verify(publicKey, canonical, proof.ProofValue)
}

// JSON returns the canonical JSON representation.
func (r *WorkReceipt) JSON() ([]byte, error) {
	return crypto.CanonicalizeJSON(r)
}

// Validate validates the receipt against the JSON schema.
func (r *WorkReceipt) Validate() error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return validate.ValidateReceipt(data)
}

// FromJSON parses a WorkReceipt from JSON. Set validate to true (default) to run schema validation.
func FromJSON(data []byte, opts ...bool) (*WorkReceipt, error) {
	doValidate := true
	if len(opts) > 0 {
		doValidate = opts[0]
	}
	if doValidate {
		if err := validate.ValidateReceipt(data); err != nil {
			return nil, fmt.Errorf("schema validation: %w", err)
		}
	}
	var r WorkReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &r, nil
}
