package did

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DIDWebResolver resolves did:web DIDs.
type DIDWebResolver struct {
	Client *http.Client
}

func NewDIDWebResolver() *DIDWebResolver {
	return &DIDWebResolver{
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (r *DIDWebResolver) Method() string { return "web" }

// ResolveDIDWebURL transforms a did:web DID to its HTTPS URL.
func ResolveDIDWebURL(did string) (string, error) {
	method, specific, err := ParseDID(did)
	if err != nil {
		return "", err
	}
	if method != "web" {
		return "", fmt.Errorf("unsupported method: %s", method)
	}

	parts := strings.Split(specific, ":")
	domain := strings.ReplaceAll(parts[0], "%3A", ":")

	if len(parts) == 1 {
		return fmt.Sprintf("https://%s/.well-known/did.json", domain), nil
	}
	path := strings.Join(parts[1:], "/")
	return fmt.Sprintf("https://%s/%s/did.json", domain, path), nil
}

func (r *DIDWebResolver) Resolve(did string) (*DIDDocument, error) {
	url, err := ResolveDIDWebURL(did)
	if err != nil {
		return nil, err
	}

	resp, err := r.Client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch did:web document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read did:web response: %w", err)
	}

	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse did:web document: %w", err)
	}
	return &doc, nil
}
