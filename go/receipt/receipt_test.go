package receipt

import (
	"testing"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
)

func testConfig() Config {
	return Config{
		ReceiptID: "550e8400-e29b-41d4-a716-446655440000",
		JobID:     "550e8400-e29b-41d4-a716-446655440001",
		AgentDID:  "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		ClientDID: "did:key:z6MkpOwnerABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
		AgentSnapshot: AgentSnapshot{
			Version: 1,
			Hash:    "0x0000000000000000000000000000000000000000000000000000000000000aaa",
		},
	}
}

func TestNew(t *testing.T) {
	r, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "WorkReceipt" {
		t.Errorf("type = %s, want WorkReceipt", r.Type)
	}
}

func TestNew_MissingFields(t *testing.T) {
	cfg := testConfig()
	cfg.ReceiptID = ""
	_, err := New(cfg)
	if err == nil {
		t.Error("should fail without receipt_id")
	}
}

func TestAddEvent(t *testing.T) {
	r, _ := New(testConfig())
	err := r.AddEvent(ReceiptEvent{
		Type:        "claim",
		Timestamp:   "2026-02-14T01:00:00Z",
		PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
		Signature:   "z_claim_sig",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 1 {
		t.Errorf("events count = %d, want 1", len(r.Events))
	}
}

func TestAddEvent_MissingType(t *testing.T) {
	r, _ := New(testConfig())
	err := r.AddEvent(ReceiptEvent{})
	if err == nil {
		t.Error("should fail without event type")
	}
}

func TestLifecycleEvents(t *testing.T) {
	r, _ := New(testConfig())
	events := []ReceiptEvent{
		{Type: "claim", Timestamp: "2026-02-14T01:00:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000001", Signature: "sig1"},
		{Type: "submit", Timestamp: "2026-02-14T01:30:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000002", Signature: "sig2"},
		{Type: "verify", Timestamp: "2026-02-14T01:35:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000003", Signature: "sig3", Result: &VerifyResult{Status: "accepted", Score: 87}},
		{Type: "payout", Timestamp: "2026-02-14T01:40:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000004", Signature: "sig4", Amount: &PayoutAmount{Value: 500, Unit: "points"}},
	}
	for _, e := range events {
		if err := r.AddEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.Events) != 4 {
		t.Errorf("events count = %d, want 4", len(r.Events))
	}
}

func TestHash_Deterministic(t *testing.T) {
	r, _ := New(testConfig())
	r.AddEvent(ReceiptEvent{Type: "claim", Timestamp: "2026-02-14T01:00:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000001", Signature: "sig"})
	h1, _ := r.Hash()
	h2, _ := r.Hash()
	if h1 != h2 {
		t.Errorf("non-deterministic: %s != %s", h1, h2)
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	r, _ := New(testConfig())
	r.AddEvent(ReceiptEvent{Type: "claim", Timestamp: "2026-02-14T01:00:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000001", Signature: "sig"})

	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	ok, err := r.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("signature should be valid")
	}
}

func TestFromJSON_Roundtrip(t *testing.T) {
	r, _ := New(testConfig())
	r.AddEvent(ReceiptEvent{Type: "claim", Timestamp: "2026-02-14T01:00:00Z", PayloadHash: "0x0000000000000000000000000000000000000000000000000000000000000001", Signature: "sig"})
	data, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := FromJSON(data, false)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ReceiptID != r.ReceiptID {
		t.Error("receipt_id mismatch")
	}
}

// === Event Chain Tests ===

func TestAddEvent_ValidType(t *testing.T) {
	r := createTestReceipt(t)
	err := r.AddEvent(ReceiptEvent{Type: "claim"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Events[0].PayloadHash == "" {
		t.Fatal("payload_hash should be computed automatically")
	}
}

func TestAddEvent_InvalidType(t *testing.T) {
	r := createTestReceipt(t)
	err := r.AddEvent(ReceiptEvent{Type: "hack"})
	if err == nil {
		t.Fatal("should reject unknown event type")
	}
}

func TestAddEvent_ChronologicalOrder(t *testing.T) {
	r := createTestReceipt(t)
	r.AddEvent(ReceiptEvent{Type: "claim", Timestamp: "2026-01-01T12:00:00Z"})
	err := r.AddEvent(ReceiptEvent{Type: "submit", Timestamp: "2026-01-01T11:00:00Z"})
	if err == nil {
		t.Fatal("should reject out-of-order timestamp")
	}
	// In order should work
	err = r.AddEvent(ReceiptEvent{Type: "submit", Timestamp: "2026-01-01T13:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEventChain(t *testing.T) {
	r := createTestReceipt(t)
	r.AddEvent(ReceiptEvent{Type: "claim", Timestamp: "2026-01-01T10:00:00Z"})
	r.AddEvent(ReceiptEvent{Type: "submit", Timestamp: "2026-01-01T11:00:00Z"})
	r.AddEvent(ReceiptEvent{Type: "verify", Timestamp: "2026-01-01T12:00:00Z"})

	err := r.VerifyEventChain()
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestVerifyEventChain_MissingHash(t *testing.T) {
	r := createTestReceipt(t)
	// Manually add event without hash
	r.Events = append(r.Events, ReceiptEvent{Type: "claim", Timestamp: "2026-01-01T10:00:00Z"})
	err := r.VerifyEventChain()
	if err == nil {
		t.Fatal("should detect missing payload_hash")
	}
}

func createTestReceipt(t *testing.T) *WorkReceipt {
	t.Helper()
	r, err := New(Config{
		ReceiptID: "receipt-test-001",
		JobID:     "job-test-001",
		AgentDID:  "did:key:z6MkAgent",
		ClientDID: "did:key:z6MkClient",
		AgentSnapshot: AgentSnapshot{Version: 1, Hash: "0x1234"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
