// Package attestation implements W3C Verifiable Credential-based attestation exchange.
package attestation

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	apscrypto "github.com/cezexPL/agent-passport-standard/go/crypto"
)

// Attestation represents a W3C Verifiable Credential for agent attestation.
type Attestation struct {
	Context      []string               `json:"@context"`
	Type         []string               `json:"type"`
	Issuer       string                 `json:"issuer"`
	IssuanceDate string                 `json:"issuanceDate"`
	ExpiresAt    string                 `json:"expirationDate,omitempty"`
	Subject      CredentialSubject      `json:"credentialSubject"`
	Proof        *AttestationProof      `json:"proof,omitempty"`
}

// CredentialSubject holds the claims about the subject.
type CredentialSubject struct {
	ID     string                 `json:"id"`
	Type   string                 `json:"type"`
	Claims map[string]interface{} `json:"claims"`
}

// AttestationProof is the Ed25519 proof over the attestation.
type AttestationProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// CreateAttestation creates a signed attestation (W3C VC).
func CreateAttestation(issuerDID, subjectDID, atType string, claims map[string]interface{}, privateKey ed25519.PrivateKey) (*Attestation, error) {
	att := &Attestation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://agentpassport.org/v0.2/attestation",
		},
		Type:         []string{"VerifiableCredential", "AgentAttestation"},
		Issuer:       issuerDID,
		IssuanceDate: time.Now().UTC().Format(time.RFC3339),
		Subject: CredentialSubject{
			ID:     subjectDID,
			Type:   atType,
			Claims: claims,
		},
	}

	// Sign: canonicalize everything except proof, then sign
	msg, err := attestationMessage(att)
	if err != nil {
		return nil, err
	}

	sig := apscrypto.Ed25519Sign(privateKey, msg)

	att.Proof = &AttestationProof{
		Type:               "Ed25519Signature2020",
		Created:            att.IssuanceDate,
		VerificationMethod: issuerDID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}

	return att, nil
}

// CreateAttestationWithExpiry creates a signed attestation with an expiration date.
func CreateAttestationWithExpiry(issuerDID, subjectDID, atType string, claims map[string]interface{}, privateKey ed25519.PrivateKey, expiresAt time.Time) (*Attestation, error) {
	att, err := CreateAttestation(issuerDID, subjectDID, atType, claims, privateKey)
	if err != nil {
		return nil, err
	}
	// Need to re-sign with the expiry set
	att.Proof = nil
	att.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)

	msg, err := attestationMessage(att)
	if err != nil {
		return nil, err
	}
	sig := apscrypto.Ed25519Sign(privateKey, msg)
	att.Proof = &AttestationProof{
		Type:               "Ed25519Signature2020",
		Created:            att.IssuanceDate,
		VerificationMethod: issuerDID + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}
	return att, nil
}

// VerifyAttestation verifies the attestation signature and checks expiry.
func VerifyAttestation(att *Attestation, publicKey ed25519.PublicKey) (bool, error) {
	if att.Proof == nil {
		return false, fmt.Errorf("no proof")
	}

	// Check expiry
	if att.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, att.ExpiresAt)
		if err != nil {
			return false, fmt.Errorf("parse expiry: %w", err)
		}
		if time.Now().UTC().After(exp) {
			return false, nil
		}
	}

	proof := att.Proof
	att.Proof = nil
	msg, err := attestationMessage(att)
	att.Proof = proof
	if err != nil {
		return false, err
	}

	sigBytes, err := hex.DecodeString(proof.ProofValue)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}

	return ed25519.Verify(publicKey, msg, sigBytes), nil
}

func attestationMessage(att *Attestation) ([]byte, error) {
	// Marshal to JSON, remove proof, canonicalize
	data, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal attestation: %w", err)
	}
	delete(m, "proof")
	canonical, err2 := apscrypto.CanonicalizeJSON(m)
	if err2 != nil {
		return nil, fmt.Errorf("canonicalize: %w", err2)
	}
	return canonical, nil
}

// AttestationRegistry is an in-memory registry of trusted issuers.
type AttestationRegistry struct {
	mu      sync.RWMutex
	issuers map[string]ed25519.PublicKey
}

// NewAttestationRegistry creates a new empty registry.
func NewAttestationRegistry() *AttestationRegistry {
	return &AttestationRegistry{
		issuers: make(map[string]ed25519.PublicKey),
	}
}

// RegisterIssuer adds a trusted issuer.
func (r *AttestationRegistry) RegisterIssuer(did string, publicKey ed25519.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issuers[did] = publicKey
}

// RemoveIssuer removes a trusted issuer.
func (r *AttestationRegistry) RemoveIssuer(did string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.issuers, did)
}

// IsTrusted checks if an issuer is in the registry.
func (r *AttestationRegistry) IsTrusted(did string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.issuers[did]
	return ok
}

// GetPublicKey returns the public key for a trusted issuer.
func (r *AttestationRegistry) GetPublicKey(did string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pk, ok := r.issuers[did]
	return pk, ok
}

// VerifyFromRegistry verifies an attestation using the registry to look up the issuer's key.
func (r *AttestationRegistry) VerifyFromRegistry(att *Attestation) (bool, error) {
	pk, ok := r.GetPublicKey(att.Issuer)
	if !ok {
		return false, fmt.Errorf("issuer %s not trusted", att.Issuer)
	}
	return VerifyAttestation(att, pk)
}
