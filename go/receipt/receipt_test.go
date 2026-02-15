package receipt

import (
	"testing"

	"github.com/agent-passport/standard-go/crypto"
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
	r2, err := FromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ReceiptID != r.ReceiptID {
		t.Error("receipt_id mismatch")
	}
}
