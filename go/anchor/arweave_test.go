package anchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestArweaveCommit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tx" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"id": "arweave-tx-id-12345",
		})
	}))
	defer server.Close()

	provider := NewArweaveProvider(ArweaveConfig{GatewayURL: server.URL})

	hash := [32]byte{1, 2, 3}
	receipt, err := provider.Commit(context.Background(), hash, AnchorMetadata{ArtifactType: "passport"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receipt.TxHash != "arweave-tx-id-12345" {
		t.Errorf("unexpected tx hash: %s", receipt.TxHash)
	}
	if receipt.Provider != "arweave" {
		t.Errorf("unexpected provider: %s", receipt.Provider)
	}
}

func TestArweaveVerifyFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{"data":{"transactions":{"edges":[{"node":{"id":"ar-tx-123","block":{"height":100,"timestamp":1700000000}}}]}}}`
		w.Write([]byte(resp))
	}))
	defer server.Close()

	provider := NewArweaveProvider(ArweaveConfig{GatewayURL: server.URL})

	hash := [32]byte{1, 2, 3}
	v, err := provider.Verify(context.Background(), hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Exists {
		t.Error("expected exists to be true")
	}
	if v.TxHash != "ar-tx-123" {
		t.Errorf("unexpected tx hash: %s", v.TxHash)
	}
	if v.Block != 100 {
		t.Errorf("expected block 100, got %d", v.Block)
	}
}

func TestArweaveVerifyNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{"data":{"transactions":{"edges":[]}}}`
		w.Write([]byte(resp))
	}))
	defer server.Close()

	provider := NewArweaveProvider(ArweaveConfig{GatewayURL: server.URL})

	hash := [32]byte{1, 2, 3}
	v, err := provider.Verify(context.Background(), hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Exists {
		t.Error("expected exists to be false")
	}
}

func TestArweaveInfo(t *testing.T) {
	provider := NewArweaveProvider(ArweaveConfig{})
	info := provider.Info()
	if info.Name != "arweave" || info.Type != "arweave" {
		t.Errorf("unexpected info: %+v", info)
	}
}
