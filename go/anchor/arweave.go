package anchor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ArweaveConfig holds configuration for the Arweave anchor provider.
type ArweaveConfig struct {
	GatewayURL string // default: https://arweave.net
	WalletJSON string // JWK wallet JSON (for signing transactions)
}

// ArweaveProvider anchors hashes to the Arweave permanent storage network.
type ArweaveProvider struct {
	cfg    ArweaveConfig
	client *http.Client
}

// NewArweaveProvider creates a new Arweave anchor provider.
func NewArweaveProvider(cfg ArweaveConfig) *ArweaveProvider {
	gw := cfg.GatewayURL
	if gw == "" {
		gw = "https://arweave.net"
	}
	cfg.GatewayURL = gw
	return &ArweaveProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetHTTPClient allows overriding the HTTP client (for testing).
func (a *ArweaveProvider) SetHTTPClient(c *http.Client) {
	a.client = c
}

// arweaveTx represents a minimal Arweave transaction for anchoring.
type arweaveTx struct {
	ID   string       `json:"id,omitempty"`
	Data string       `json:"data"`
	Tags []arweaveTag `json:"tags"`
}

type arweaveTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Commit posts a transaction to Arweave with the hash as a tag.
func (a *ArweaveProvider) Commit(ctx context.Context, hash [32]byte, meta AnchorMetadata) (AnchorReceipt, error) {
	hashHex := "0x" + hex.EncodeToString(hash[:])

	tx := arweaveTx{
		Data: hashHex,
		Tags: []arweaveTag{
			{Name: "App-Name", Value: "AgentPassportStandard"},
			{Name: "APS-Hash", Value: hashHex},
			{Name: "APS-Type", Value: meta.ArtifactType},
			{Name: "Content-Type", Value: "text/plain"},
		},
	}

	body, err := json.Marshal(tx)
	if err != nil {
		return AnchorReceipt{}, fmt.Errorf("marshal tx: %w", err)
	}

	url := a.cfg.GatewayURL + "/tx"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return AnchorReceipt{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return AnchorReceipt{}, fmt.Errorf("post tx: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return AnchorReceipt{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return AnchorReceipt{}, fmt.Errorf("arweave error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		// Some gateways return just the ID as plain text
		result.ID = string(respBody)
	}

	return AnchorReceipt{
		TxHash:    result.ID,
		Block:     0,
		Timestamp: time.Now().UTC(),
		Provider:  "arweave",
	}, nil
}

// Verify checks if a hash has been anchored on Arweave by querying GraphQL.
func (a *ArweaveProvider) Verify(ctx context.Context, hash [32]byte) (AnchorVerification, error) {
	hashHex := "0x" + hex.EncodeToString(hash[:])

	query := map[string]interface{}{
		"query": `query($hash: String!) {
			transactions(tags: [{name: "APS-Hash", values: [$hash]}], first: 1) {
				edges {
					node {
						id
						block { height timestamp }
					}
				}
			}
		}`,
		"variables": map[string]string{"hash": hashHex},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return AnchorVerification{}, fmt.Errorf("marshal query: %w", err)
	}

	url := a.cfg.GatewayURL + "/graphql"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return AnchorVerification{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return AnchorVerification{}, fmt.Errorf("graphql query: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return AnchorVerification{}, fmt.Errorf("read response: %w", err)
	}

	var gqlResp struct {
		Data struct {
			Transactions struct {
				Edges []struct {
					Node struct {
						ID    string `json:"id"`
						Block *struct {
							Height    int64 `json:"height"`
							Timestamp int64 `json:"timestamp"`
						} `json:"block"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"transactions"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return AnchorVerification{}, fmt.Errorf("unmarshal graphql response: %w", err)
	}

	edges := gqlResp.Data.Transactions.Edges
	if len(edges) == 0 {
		return AnchorVerification{Exists: false}, nil
	}

	node := edges[0].Node
	v := AnchorVerification{
		Exists: true,
		TxHash: node.ID,
	}
	if node.Block != nil {
		v.Block = node.Block.Height
		v.Timestamp = time.Unix(node.Block.Timestamp, 0).UTC()
	}

	return v, nil
}

// Info returns provider metadata.
func (a *ArweaveProvider) Info() ProviderInfo {
	return ProviderInfo{
		Name:    "arweave",
		ChainID: "arweave-mainnet",
		Type:    "arweave",
	}
}
