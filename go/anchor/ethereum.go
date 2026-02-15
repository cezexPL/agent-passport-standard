package anchor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EthereumConfig holds configuration for the Ethereum anchor provider.
type EthereumConfig struct {
	RPCURL          string
	PrivateKey      string // hex-encoded (no 0x prefix needed)
	ContractAddress string // 0x-prefixed
	ChainID         int    // e.g. 1 for mainnet, 8453 for Base
	FromAddress     string // 0x-prefixed sender address
}

// EthereumProvider anchors hashes to any EVM-compatible blockchain.
type EthereumProvider struct {
	cfg    EthereumConfig
	client *http.Client
}

// NewEthereumProvider creates a new Ethereum anchor provider.
func NewEthereumProvider(cfg EthereumConfig) *EthereumProvider {
	return &EthereumProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetHTTPClient allows overriding the HTTP client (for testing).
func (e *EthereumProvider) SetHTTPClient(c *http.Client) {
	e.client = c
}

type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int             `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *EthereumProvider) rpcCall(ctx context.Context, method string, params []interface{}) (json.RawMessage, error) {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal rpc request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", e.cfg.RPCURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rpc call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal rpc response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// anchor(bytes32) function selector = keccak256("anchor(bytes32)")[:4]
const anchorSelector = "0xc2b12a73"

// isAnchored(bytes32) function selector = keccak256("isAnchored(bytes32)")[:4]
const isAnchoredSelector = "0xa85f7489"

func encodeBytes32Call(selector string, hash [32]byte) string {
	return selector + hex.EncodeToString(hash[:])
}

// Commit anchors a hash on the EVM chain by calling anchor(bytes32).
func (e *EthereumProvider) Commit(ctx context.Context, hash [32]byte, _ AnchorMetadata) (AnchorReceipt, error) {
	data := encodeBytes32Call(anchorSelector, hash)

	txObj := map[string]string{
		"from": e.cfg.FromAddress,
		"to":   e.cfg.ContractAddress,
		"data": data,
	}

	result, err := e.rpcCall(ctx, "eth_sendTransaction", []interface{}{txObj})
	if err != nil {
		return AnchorReceipt{}, fmt.Errorf("eth_sendTransaction: %w", err)
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return AnchorReceipt{}, fmt.Errorf("unmarshal tx hash: %w", err)
	}

	// Get transaction receipt for block number
	receiptResult, err := e.rpcCall(ctx, "eth_getTransactionReceipt", []interface{}{txHash})
	if err != nil {
		return AnchorReceipt{
			TxHash:    txHash,
			Block:     0,
			Timestamp: time.Now().UTC(),
			Provider:  "ethereum",
		}, nil
	}

	var receipt struct {
		BlockNumber string `json:"blockNumber"`
	}
	if err := json.Unmarshal(receiptResult, &receipt); err == nil && receipt.BlockNumber != "" {
		block := parseHexInt64(receipt.BlockNumber)
		return AnchorReceipt{
			TxHash:    txHash,
			Block:     block,
			Timestamp: time.Now().UTC(),
			Provider:  "ethereum",
		}, nil
	}

	return AnchorReceipt{
		TxHash:    txHash,
		Block:     0,
		Timestamp: time.Now().UTC(),
		Provider:  "ethereum",
	}, nil
}

// Verify checks if a hash has been anchored by calling isAnchored(bytes32).
func (e *EthereumProvider) Verify(ctx context.Context, hash [32]byte) (AnchorVerification, error) {
	data := encodeBytes32Call(isAnchoredSelector, hash)

	callObj := map[string]string{
		"to":   e.cfg.ContractAddress,
		"data": data,
	}

	result, err := e.rpcCall(ctx, "eth_call", []interface{}{callObj, "latest"})
	if err != nil {
		return AnchorVerification{}, fmt.Errorf("eth_call: %w", err)
	}

	var resultHex string
	if err := json.Unmarshal(result, &resultHex); err != nil {
		return AnchorVerification{}, fmt.Errorf("unmarshal call result: %w", err)
	}

	// ABI-encoded bool: 32 bytes, last byte is 0 or 1
	isAnchored := false
	clean := strings.TrimPrefix(resultHex, "0x")
	if len(clean) >= 64 {
		isAnchored = clean[63] == '1'
	}

	if !isAnchored {
		return AnchorVerification{Exists: false}, nil
	}

	return AnchorVerification{
		Exists:    true,
		Timestamp: time.Now().UTC(),
	}, nil
}

// Info returns provider metadata.
func (e *EthereumProvider) Info() ProviderInfo {
	return ProviderInfo{
		Name:    "ethereum",
		ChainID: e.cfg.ChainID,
		Type:    "ethereum",
	}
}

func parseHexInt64(s string) int64 {
	s = strings.TrimPrefix(s, "0x")
	var n int64
	for _, c := range s {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += int64(c - '0')
		case c >= 'a' && c <= 'f':
			n += int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += int64(c-'A') + 10
		}
	}
	return n
}
