package did

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

// DIDKeyResolver resolves did:key DIDs.
type DIDKeyResolver struct{}

func NewDIDKeyResolver() *DIDKeyResolver { return &DIDKeyResolver{} }

func (r *DIDKeyResolver) Method() string { return "key" }

func (r *DIDKeyResolver) Resolve(did string) (*DIDDocument, error) {
	method, specific, err := ParseDID(did)
	if err != nil {
		return nil, err
	}
	if method != "key" {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	if !strings.HasPrefix(specific, "z") {
		return nil, errors.New("did:key multibase must start with 'z' (base58btc)")
	}

	raw, err := DecodeBase58BTC(specific[1:])
	if err != nil {
		return nil, fmt.Errorf("base58btc decode: %w", err)
	}

	// Expect 0xed01 multicodec prefix for Ed25519
	if len(raw) < 2 || raw[0] != 0xed || raw[1] != 0x01 {
		return nil, errors.New("unsupported key type: expected Ed25519 multicodec prefix 0xed01")
	}

	pubBytes := raw[2:]
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}

	// Re-encode with multibase prefix for the document
	multibaseKey := "z" + EncodeBase58BTC(raw)
	vmID := did + "#" + specific

	return &DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"},
		ID:      did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 vmID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: multibaseKey,
			},
		},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}, nil
}
