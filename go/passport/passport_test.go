package passport

import (
	"testing"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
)

func testConfig() Config {
	return Config{
		ID:        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		PublicKey: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		OwnerDID:  "did:key:z6MkpOwnerABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
		Skills: []Skill{
			{
				Name:         "go-developer",
				Version:      "1.0.0",
				Description:  "Go backend development",
				Capabilities: []string{"code_write", "test_run"},
				Hash:         "0x0000000000000000000000000000000000000000000000000000000000000001",
			},
		},
		Soul: Soul{
			Personality: "focused",
			WorkStyle:   "test-first",
			Constraints: []string{"deterministic"},
			Hash:        "0x0000000000000000000000000000000000000000000000000000000000000002",
			Frozen:      false,
		},
		Policies: Policies{
			PolicySetHash: "0x0000000000000000000000000000000000000000000000000000000000000003",
			Summary:       []string{"can_bid"},
		},
		Lineage: Lineage{
			Kind:       "single",
			Parents:    []string{},
			Generation: 0,
		},
	}
}

func TestNew(t *testing.T) {
	p, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "AgentPassport" {
		t.Errorf("type = %s, want AgentPassport", p.Type)
	}
	if p.Snapshot.Version != 1 {
		t.Errorf("version = %d, want 1", p.Snapshot.Version)
	}
	if p.Snapshot.Hash == "" {
		t.Error("snapshot hash should not be empty")
	}
	if p.GenesisOwner.Immutable != true {
		t.Error("genesis_owner.immutable should be true")
	}
}

func TestNew_MissingID(t *testing.T) {
	cfg := testConfig()
	cfg.ID = ""
	_, err := New(cfg)
	if err == nil {
		t.Error("should fail without id")
	}
}

func TestHash_Deterministic(t *testing.T) {
	p, _ := New(testConfig())
	h1, err := p.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := p.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic: %s != %s", h1, h2)
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if p.Proof == nil {
		t.Fatal("proof should be set")
	}
	ok, err := p.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("signature should be valid")
	}
}

func TestSignVerify_WrongKey(t *testing.T) {
	_, priv, _ := crypto.GenerateKeyPair()
	pub2, _, _ := crypto.GenerateKeyPair()

	p, _ := New(testConfig())
	p.Sign(priv)

	ok, err := p.Verify(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("should not verify with wrong key")
	}
}

func TestFromJSON_Roundtrip(t *testing.T) {
	p, _ := New(testConfig())
	data, err := p.JSON()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := FromJSON(data, false)
	if err != nil {
		t.Fatal(err)
	}
	if p2.ID != p.ID {
		t.Errorf("id mismatch: %s != %s", p2.ID, p.ID)
	}
	if p2.Snapshot.Hash != p.Snapshot.Hash {
		t.Error("snapshot hash mismatch after roundtrip")
	}
}

// === UpdateSnapshot Tests ===

func TestUpdateSnapshot_VersionIncrement(t *testing.T) {
	p, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if p.Snapshot.Version != 1 {
		t.Fatalf("initial version = %d, want 1", p.Snapshot.Version)
	}
	if p.Snapshot.PrevHash != nil {
		t.Fatal("initial prev_hash should be nil")
	}
	oldHash := p.Snapshot.Hash

	err = p.UpdateSnapshot(SnapshotUpdate{
		Skills: []Skill{{Name: "rust-dev", Version: "1.0.0", Description: "Rust", Capabilities: []string{"code_write"}, Hash: "0x0001"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Snapshot.Version != 2 {
		t.Fatalf("version = %d, want 2", p.Snapshot.Version)
	}
	if p.Snapshot.PrevHash == nil || *p.Snapshot.PrevHash != oldHash {
		t.Fatalf("prev_hash should be %s", oldHash)
	}
	if p.Snapshot.Hash == oldHash {
		t.Fatal("hash should change after update")
	}
	if p.Proof != nil {
		t.Fatal("proof should be invalidated after update")
	}
}

func TestUpdateSnapshot_FrozenSkills(t *testing.T) {
	p, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Freeze skills
	err = p.UpdateSnapshot(SnapshotUpdate{FreezeSkills: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Snapshot.Skills.Frozen {
		t.Fatal("skills should be frozen")
	}
	// Try to update frozen skills
	err = p.UpdateSnapshot(SnapshotUpdate{
		Skills: []Skill{{Name: "nope", Version: "1.0.0", Description: "blocked", Capabilities: []string{"x"}, Hash: "0x0002"}},
	})
	if err == nil {
		t.Fatal("should reject skill update when frozen")
	}
}

func TestUpdateSnapshot_FrozenSoul(t *testing.T) {
	p, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	err = p.UpdateSnapshot(SnapshotUpdate{FreezeSoul: true})
	if err != nil {
		t.Fatal(err)
	}
	err = p.UpdateSnapshot(SnapshotUpdate{
		Soul: &Soul{Personality: "evil", WorkStyle: "chaos", Constraints: nil, Hash: "0x666", Frozen: false},
	})
	if err == nil {
		t.Fatal("should reject soul update when frozen")
	}
}

func TestValidateSnapshotChain(t *testing.T) {
	p, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Version 1, no history
	err = ValidateSnapshotChain(p, nil)
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}

	// Build history
	snap1 := p.Snapshot
	p.UpdateSnapshot(SnapshotUpdate{
		Skills: []Skill{{Name: "v2-skill", Version: "1.0.0", Description: "v2", Capabilities: []string{"a"}, Hash: "0x0005"}},
	})

	err = ValidateSnapshotChain(p, []Snapshot{snap1})
	if err != nil {
		t.Fatalf("valid 2-version chain rejected: %v", err)
	}

	// Break chain — wrong version
	p.Snapshot.Version = 99
	err = ValidateSnapshotChain(p, []Snapshot{snap1})
	if err == nil {
		t.Fatal("broken chain should fail")
	}
}
