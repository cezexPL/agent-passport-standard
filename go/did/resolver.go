package did

import (
	"crypto/ed25519"
	"errors"
	"strings"
)

// DIDDocument represents a W3C DID Document.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// Resolver resolves DIDs to DID Documents.
type Resolver interface {
	Resolve(did string) (*DIDDocument, error)
	Method() string
}

// ParseDID parses a DID string into method and method-specific-id.
func ParseDID(did string) (method, specific string, err error) {
	if !strings.HasPrefix(did, "did:") {
		return "", "", errors.New("invalid DID: must start with 'did:'")
	}
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return "", "", errors.New("invalid DID: must have method and method-specific-id")
	}
	return parts[1], parts[2], nil
}

// GenerateDIDWeb generates a did:web DID from a domain and optional path segments.
func GenerateDIDWeb(domain string, paths ...string) string {
	parts := append([]string{"did", "web", domain}, paths...)
	return strings.Join(parts, ":")
}

// ExtractPublicKey extracts the first Ed25519 public key from a DID Document.
func ExtractPublicKey(doc *DIDDocument) (ed25519.PublicKey, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.Type == "Ed25519VerificationKey2020" && strings.HasPrefix(vm.PublicKeyMultibase, "z") {
			raw, err := DecodeBase58BTC(vm.PublicKeyMultibase[1:])
			if err != nil {
				return nil, err
			}
			// Strip multicodec 0xed01 header if present
			if len(raw) >= 2 && raw[0] == 0xed && raw[1] == 0x01 {
				raw = raw[2:]
			}
			if len(raw) != ed25519.PublicKeySize {
				return nil, errors.New("invalid Ed25519 public key length")
			}
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, errors.New("no Ed25519 verification method found")
}
