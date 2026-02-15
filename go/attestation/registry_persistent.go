package attestation

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// IssuerEntry represents a trusted issuer stored in the file registry.
type IssuerEntry struct {
	DID        string    `json:"did"`
	PublicKey  []byte    `json:"public_key"`
	Name       string    `json:"name,omitempty"`
	Platform   string    `json:"platform,omitempty"`
	AddedAt    time.Time `json:"added_at"`
	TrustLevel int       `json:"trust_level"`
}

// IssuerOption configures optional fields on an IssuerEntry.
type IssuerOption func(*IssuerEntry)

// WithName sets the issuer name.
func WithName(name string) IssuerOption {
	return func(e *IssuerEntry) { e.Name = name }
}

// WithPlatform sets the issuer platform.
func WithPlatform(platform string) IssuerOption {
	return func(e *IssuerEntry) { e.Platform = platform }
}

// WithTrustLevel sets the trust level (0-3).
func WithTrustLevel(level int) IssuerOption {
	return func(e *IssuerEntry) { e.TrustLevel = level }
}

// FileRegistry stores trusted issuers in a JSON file.
type FileRegistry struct {
	mu      sync.RWMutex
	path    string
	issuers map[string]IssuerEntry
}

// NewFileRegistry creates or loads a file-backed registry.
func NewFileRegistry(path string) (*FileRegistry, error) {
	r := &FileRegistry{
		path:    path,
		issuers: make(map[string]IssuerEntry),
	}
	if _, err := os.Stat(path); err == nil {
		if err := r.Load(); err != nil {
			return nil, fmt.Errorf("load registry: %w", err)
		}
	}
	return r, nil
}

// RegisterIssuer adds a trusted issuer to the registry and saves.
func (r *FileRegistry) RegisterIssuer(did string, publicKey ed25519.PublicKey, opts ...IssuerOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := IssuerEntry{
		DID:       did,
		PublicKey: []byte(publicKey),
		AddedAt:   time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(&entry)
	}
	r.issuers[did] = entry
	return r.saveLocked()
}

// RemoveIssuer removes a trusted issuer and saves.
func (r *FileRegistry) RemoveIssuer(did string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.issuers, did)
	return r.saveLocked()
}

// IsTrusted checks if an issuer is registered.
func (r *FileRegistry) IsTrusted(did string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.issuers[did]
	return ok
}

// GetPublicKey returns the public key for a trusted issuer.
func (r *FileRegistry) GetPublicKey(did string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.issuers[did]
	if !ok {
		return nil, false
	}
	return ed25519.PublicKey(e.PublicKey), true
}

// VerifyAttestation verifies an attestation by looking up the issuer key.
func (r *FileRegistry) VerifyAttestation(att *Attestation) (bool, error) {
	pk, ok := r.GetPublicKey(att.Issuer)
	if !ok {
		return false, fmt.Errorf("issuer %s not trusted", att.Issuer)
	}
	return VerifyAttestation(att, pk)
}

// ListIssuers returns all registered issuers.
func (r *FileRegistry) ListIssuers() []IssuerEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]IssuerEntry, 0, len(r.issuers))
	for _, e := range r.issuers {
		out = append(out, e)
	}
	return out
}

// Save persists the registry to disk.
func (r *FileRegistry) Save() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.saveLocked()
}

func (r *FileRegistry) saveLocked() error {
	data, err := json.MarshalIndent(r.issuers, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0644)
}

// Load reads the registry from disk.
func (r *FileRegistry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	issuers := make(map[string]IssuerEntry)
	if err := json.Unmarshal(data, &issuers); err != nil {
		return err
	}
	r.issuers = issuers
	return nil
}

// Export returns the registry as JSON for federation.
func (r *FileRegistry) Export() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.MarshalIndent(r.issuers, "", "  ")
}

// ImportFrom merges issuers from a remote registry JSON. Returns count of new issuers added.
func (r *FileRegistry) ImportFrom(data []byte) (int, error) {
	var remote map[string]IssuerEntry
	if err := json.Unmarshal(data, &remote); err != nil {
		return 0, fmt.Errorf("unmarshal remote: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	added := 0
	for did, entry := range remote {
		if _, exists := r.issuers[did]; !exists {
			r.issuers[did] = entry
			added++
		}
	}
	if added > 0 {
		if err := r.saveLocked(); err != nil {
			return added, err
		}
	}
	return added, nil
}
