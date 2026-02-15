package anchor

import (
	"context"
	"encoding/hex"
	"time"
)

// NoOpProvider is a no-op anchoring provider for testing.
type NoOpProvider struct{}

// NewNoOpProvider creates a new NoOpProvider.
func NewNoOpProvider() *NoOpProvider {
	return &NoOpProvider{}
}

func (n *NoOpProvider) Commit(_ context.Context, hash [32]byte, _ AnchorMetadata) (AnchorReceipt, error) {
	return AnchorReceipt{
		TxHash:    "0x" + hex.EncodeToString(hash[:]),
		Block:     1,
		Timestamp: time.Now().UTC(),
		Provider:  "noop",
	}, nil
}

func (n *NoOpProvider) Verify(_ context.Context, hash [32]byte) (AnchorVerification, error) {
	return AnchorVerification{
		Exists:    true,
		TxHash:    "0x" + hex.EncodeToString(hash[:]),
		Block:     1,
		Timestamp: time.Now().UTC(),
	}, nil
}

func (n *NoOpProvider) Info() ProviderInfo {
	return ProviderInfo{
		Name:    "noop",
		ChainID: "0",
		Type:    "noop",
	}
}
