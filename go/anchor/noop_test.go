package anchor

import (
	"context"
	"testing"
)

func TestNoOpProvider_Commit(t *testing.T) {
	p := NewNoOpProvider()
	hash := [32]byte{1, 2, 3}
	receipt, err := p.Commit(context.Background(), hash, AnchorMetadata{ArtifactType: "passport"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Provider != "noop" {
		t.Errorf("provider = %s, want noop", receipt.Provider)
	}
	if receipt.TxHash == "" {
		t.Error("tx_hash should not be empty")
	}
}

func TestNoOpProvider_Verify(t *testing.T) {
	p := NewNoOpProvider()
	hash := [32]byte{1, 2, 3}
	v, err := p.Verify(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Exists {
		t.Error("should always exist for noop")
	}
}

func TestNoOpProvider_Info(t *testing.T) {
	p := NewNoOpProvider()
	info := p.Info()
	if info.Type != "noop" {
		t.Errorf("type = %s, want noop", info.Type)
	}
}

func TestNoOpProvider_ImplementsInterface(t *testing.T) {
	var _ AnchorProvider = (*NoOpProvider)(nil)
}
