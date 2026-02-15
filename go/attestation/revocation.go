package attestation

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	apscrypto "github.com/cezexPL/agent-passport-standard/go/crypto"
)

// RevocationList tracks revoked attestation hashes, signed by the issuer.
type RevocationList struct {
	Issuer    string            `json:"issuer"`
	Revoked   []string          `json:"revoked"`
	UpdatedAt string            `json:"updated_at"`
	Proof     *AttestationProof `json:"proof,omitempty"`
}

// NewRevocationList creates an empty revocation list for the given issuer.
func NewRevocationList(issuerDID string) *RevocationList {
	return &RevocationList{
		Issuer:    issuerDID,
		Revoked:   []string{},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// Revoke adds an attestation hash to the revocation list.
func (rl *RevocationList) Revoke(attestationHash string) {
	for _, h := range rl.Revoked {
		if h == attestationHash {
			return
		}
	}
	rl.Revoked = append(rl.Revoked, attestationHash)
	rl.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	rl.Proof = nil // invalidate old proof
}

// IsRevoked checks if a hash is in the revocation list.
func (rl *RevocationList) IsRevoked(attestationHash string) bool {
	for _, h := range rl.Revoked {
		if h == attestationHash {
			return true
		}
	}
	return false
}

func (rl *RevocationList) message() ([]byte, error) {
	data, err := json.Marshal(rl)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	delete(m, "proof")
	return apscrypto.CanonicalizeJSON(m)
}

// Sign signs the revocation list with the issuer's private key.
func (rl *RevocationList) Sign(issuerPrivKey ed25519.PrivateKey) error {
	rl.Proof = nil
	msg, err := rl.message()
	if err != nil {
		return err
	}
	sig := apscrypto.Ed25519Sign(issuerPrivKey, msg)
	rl.Proof = &AttestationProof{
		Type:               "Ed25519Signature2020",
		Created:            rl.UpdatedAt,
		VerificationMethod: rl.Issuer + "#key-1",
		ProofPurpose:       "assertionMethod",
		ProofValue:         sig,
	}
	return nil
}

// Verify checks the revocation list signature.
func (rl *RevocationList) Verify(issuerPubKey ed25519.PublicKey) (bool, error) {
	if rl.Proof == nil {
		return false, fmt.Errorf("no proof")
	}
	proof := rl.Proof
	rl.Proof = nil
	msg, err := rl.message()
	rl.Proof = proof
	if err != nil {
		return false, err
	}
	return apscrypto.Ed25519Verify(issuerPubKey, msg, proof.ProofValue)
}

// JSON serializes the revocation list.
func (rl *RevocationList) JSON() ([]byte, error) {
	return json.MarshalIndent(rl, "", "  ")
}

// RevocationListFromJSON deserializes a revocation list.
func RevocationListFromJSON(data []byte) (*RevocationList, error) {
	var rl RevocationList
	if err := json.Unmarshal(data, &rl); err != nil {
		return nil, err
	}
	return &rl, nil
}

// CheckRevocation verifies an attestation is not revoked. Returns true if valid (not revoked).
func CheckRevocation(att *Attestation, revList *RevocationList) (bool, error) {
	hash, err := apscrypto.HashExcludingFields(att, "proof")
	if err != nil {
		return false, fmt.Errorf("hash attestation: %w", err)
	}
	if revList.IsRevoked(hash) {
		return false, nil
	}
	return true, nil
}
