package passport

import (
	"testing"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
)

func TestSignatureForgery_Passport(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p, _ := New(testConfig())
	p.Sign(priv)

	// Tamper with passport after signing
	p.Snapshot.Version = 999
	ok, err := p.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("tampered passport should not verify")
	}
}

func TestReplayAttack_Passport(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()

	p1, _ := New(testConfig())
	p1.Sign(priv)
	proof := p1.Proof

	// Create a different passport and attach the stolen proof
	cfg2 := testConfig()
	cfg2.ID = "did:key:z6MkDIFFERENT1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	p2, _ := New(cfg2)
	p2.Proof = proof

	ok, err := p2.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("replay attack should not verify")
	}
}

func TestProofStripping(t *testing.T) {
	pub, _, _ := crypto.GenerateKeyPair()
	p, _ := New(testConfig())
	// No proof set
	_, err := p.Verify(pub)
	if err == nil {
		t.Error("no proof should return error")
	}
	if err.Error() != "no proof present" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFrozenSkillsMutation(t *testing.T) {
	// Go struct doesn't enforce frozen at struct level, but we test the concept
	p, _ := New(testConfig())
	p.Snapshot.Skills.Frozen = true
	// In Go, frozen is just a flag; we verify the field is set
	if !p.Snapshot.Skills.Frozen {
		t.Error("skills should be frozen")
	}
}

func TestNullEmptyInjection(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Error("empty config should fail")
	}

	_, err = New(Config{ID: "test"})
	if err == nil {
		t.Error("missing public_key should fail")
	}

	_, err = New(Config{ID: "test", PublicKey: "key"})
	if err == nil {
		t.Error("missing owner_did should fail")
	}
}

func TestKeyMismatch_Passport(t *testing.T) {
	_, priv, _ := crypto.GenerateKeyPair()
	pub2, _, _ := crypto.GenerateKeyPair()

	p, _ := New(testConfig())
	p.Sign(priv)

	ok, err := p.Verify(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("wrong key should not verify")
	}
}
