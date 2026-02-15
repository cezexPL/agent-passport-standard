package anchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEthereumCommit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		switch req.Method {
		case "eth_sendTransaction":
			json.NewEncoder(w).Encode(jsonRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"`),
				ID:      1,
			})
		case "eth_getTransactionReceipt":
			json.NewEncoder(w).Encode(jsonRPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"blockNumber":"0xa"}`),
				ID:      1,
			})
		default:
			t.Errorf("unexpected RPC method: %s", req.Method)
		}
	}))
	defer server.Close()

	provider := NewEthereumProvider(EthereumConfig{
		RPCURL:          server.URL,
		ContractAddress: "0x1234567890123456789012345678901234567890",
		ChainID:         1,
		FromAddress:     "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})

	hash := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	receipt, err := provider.Commit(context.Background(), hash, AnchorMetadata{ArtifactType: "passport"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receipt.TxHash != "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("unexpected tx hash: %s", receipt.TxHash)
	}
	if receipt.Block != 10 {
		t.Errorf("expected block 10, got %d", receipt.Block)
	}
	if receipt.Provider != "ethereum" {
		t.Errorf("expected provider ethereum, got %s", receipt.Provider)
	}
}

func TestEthereumVerify(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return ABI-encoded true (32 bytes, last byte = 1)
		result := "0x0000000000000000000000000000000000000000000000000000000000000001"
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Result:  json.RawMessage(`"` + result + `"`),
			ID:      1,
		})
	}))
	defer server.Close()

	provider := NewEthereumProvider(EthereumConfig{
		RPCURL:          server.URL,
		ContractAddress: "0x1234567890123456789012345678901234567890",
		ChainID:         1,
		FromAddress:     "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})

	hash := [32]byte{1, 2, 3}
	v, err := provider.Verify(context.Background(), hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Exists {
		t.Error("expected exists to be true")
	}
}

func TestEthereumVerifyNotAnchored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := "0x0000000000000000000000000000000000000000000000000000000000000000"
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Result:  json.RawMessage(`"` + result + `"`),
			ID:      1,
		})
	}))
	defer server.Close()

	provider := NewEthereumProvider(EthereumConfig{
		RPCURL:          server.URL,
		ContractAddress: "0x1234567890123456789012345678901234567890",
		ChainID:         1,
	})

	hash := [32]byte{1, 2, 3}
	v, err := provider.Verify(context.Background(), hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Exists {
		t.Error("expected exists to be false")
	}
}

func TestEthereumInfo(t *testing.T) {
	provider := NewEthereumProvider(EthereumConfig{ChainID: 8453})
	info := provider.Info()
	if info.Name != "ethereum" || info.ChainID != 8453 || info.Type != "ethereum" {
		t.Errorf("unexpected info: %+v", info)
	}
}
