package identity

import (
	"encoding/json"
	"testing"
	"time"
)

func TestKeyRotationRoundTrip(t *testing.T) {
	r := KeyRotation{
		Type:      "KeyRotation",
		OldDID:    "did:key:old",
		NewDID:    "did:key:new",
		Reason:    "scheduled",
		RotatedAt: time.Now().UTC().Truncate(time.Millisecond),
		Proof:     "sig123",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var r2 KeyRotation
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r2.OldDID != r.OldDID || r2.NewDID != r.NewDID {
		t.Error("DID mismatch")
	}
}

func TestKeyRotationValidate(t *testing.T) {
	r := KeyRotation{OldDID: "did:key:old", NewDID: "did:key:new", Proof: "sig"}
	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	bad := KeyRotation{OldDID: "did:key:same", NewDID: "did:key:same", Proof: "sig"}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for same DIDs")
	}
}

func TestIdentityChain(t *testing.T) {
	chain := &IdentityChain{}
	now := time.Now().UTC()
	chain.Append("did:key:1", now)
	chain.Append("did:key:2", now.Add(time.Hour))
	chain.Append("did:key:3", now.Add(2*time.Hour))

	if chain.Len() != 3 {
		t.Errorf("len: got %d, want 3", chain.Len())
	}
	if chain.Current() != "did:key:3" {
		t.Errorf("current: got %q", chain.Current())
	}
	if chain.Head.RevokedAt == nil {
		t.Error("first node should be revoked")
	}
}

func TestRecoveryRequestRoundTrip(t *testing.T) {
	r := RecoveryRequest{
		Type:        "RecoveryRequest",
		LostDID:     "did:key:lost",
		RecoveryDID: "did:key:recovery",
		Evidence:    []string{"proof1"},
		RequestedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var r2 RecoveryRequest
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r2.LostDID != r.LostDID {
		t.Error("lostDid mismatch")
	}
}

func TestRecoveryRequestValidate(t *testing.T) {
	bad := RecoveryRequest{}
	if err := bad.Validate(); err == nil {
		t.Error("expected error")
	}
}
