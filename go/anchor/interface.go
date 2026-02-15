// Package anchor defines the anchoring provider interface for the Agent Passport Standard v0.1.
package anchor

import (
	"context"
	"time"
)

// AnchorProvider is the interface for committing artifact hashes to immutable ledgers.
type AnchorProvider interface {
	// Commit stores a hash on the anchoring layer.
	Commit(ctx context.Context, hash [32]byte, meta AnchorMetadata) (AnchorReceipt, error)
	// Verify checks if a hash has been anchored.
	Verify(ctx context.Context, hash [32]byte) (AnchorVerification, error)
	// Info returns provider metadata.
	Info() ProviderInfo
}

// AnchorReceipt is returned after a successful commit.
type AnchorReceipt struct {
	TxHash    string    `json:"tx_hash"`
	Block     int64     `json:"block"`
	Timestamp time.Time `json:"timestamp"`
	Provider  string    `json:"provider"`
}

// AnchorVerification is returned by Verify.
type AnchorVerification struct {
	Exists    bool      `json:"exists"`
	TxHash    string    `json:"tx_hash,omitempty"`
	Block     int64     `json:"block,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// ProviderInfo describes the anchoring provider.
type ProviderInfo struct {
	Name    string `json:"name"`
	ChainID string `json:"chain_id"`
	Type    string `json:"type"` // "ethereum", "arweave", "transparency-log", "noop"
}

// AnchorMetadata provides context for the commit.
type AnchorMetadata struct {
	ArtifactType string `json:"artifact_type"` // "passport", "receipt", "envelope"
	Description  string `json:"description"`
}
