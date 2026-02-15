package attestation

import (
	"os"
	"path/filepath"
	"testing"

	apscrypto "github.com/cezexPL/agent-passport-standard/go/crypto"
)

func TestFileRegistry_SaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")

	pub, _, err := apscrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	reg, err := NewFileRegistry(path)
	if err != nil {
		t.Fatal(err)
	}

	did := "did:web:example.com:agent1"
	if err := reg.RegisterIssuer(did, pub, WithName("Agent1"), WithPlatform("did:web:example.com"), WithTrustLevel(2)); err != nil {
		t.Fatal(err)
	}

	if !reg.IsTrusted(did) {
		t.Fatal("expected trusted")
	}

	// Reload from disk
	reg2, err := NewFileRegistry(path)
	if err != nil {
		t.Fatal(err)
	}

	if !reg2.IsTrusted(did) {
		t.Fatal("expected trusted after reload")
	}

	issuers := reg2.ListIssuers()
	if len(issuers) != 1 {
		t.Fatalf("expected 1 issuer, got %d", len(issuers))
	}
	if issuers[0].Name != "Agent1" || issuers[0].TrustLevel != 2 {
		t.Fatalf("unexpected entry: %+v", issuers[0])
	}
}

func TestFileRegistry_ImportFrom(t *testing.T) {
	dir := t.TempDir()

	pub1, _, _ := apscrypto.GenerateKeyPair()
	pub2, _, _ := apscrypto.GenerateKeyPair()

	// Registry A
	regA, _ := NewFileRegistry(filepath.Join(dir, "a.json"))
	regA.RegisterIssuer("did:a", pub1)

	// Registry B
	regB, _ := NewFileRegistry(filepath.Join(dir, "b.json"))
	regB.RegisterIssuer("did:b", pub2)

	// Export B, import into A
	data, err := regB.Export()
	if err != nil {
		t.Fatal(err)
	}

	added, err := regA.ImportFrom(data)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("expected 1 added, got %d", added)
	}
	if !regA.IsTrusted("did:b") {
		t.Fatal("expected did:b trusted after import")
	}

	// Import again — no duplicates
	added2, _ := regA.ImportFrom(data)
	if added2 != 0 {
		t.Fatalf("expected 0 added on re-import, got %d", added2)
	}
}

func TestFileRegistry_VerifyAttestation(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := apscrypto.GenerateKeyPair()

	reg, _ := NewFileRegistry(filepath.Join(dir, "reg.json"))
	issuerDID := "did:web:issuer.example"
	reg.RegisterIssuer(issuerDID, pub)

	att, err := CreateAttestation(issuerDID, "did:web:subject", "identity", map[string]interface{}{"level": "verified"}, priv)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := reg.VerifyAttestation(att)
	if err != nil || !ok {
		t.Fatalf("expected valid, got ok=%v err=%v", ok, err)
	}

	// Unknown issuer
	reg.RemoveIssuer(issuerDID)
	_, err = reg.VerifyAttestation(att)
	if err == nil {
		t.Fatal("expected error for unknown issuer")
	}
}

func TestFileRegistry_RemoveIssuer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reg.json")
	pub, _, _ := apscrypto.GenerateKeyPair()

	reg, _ := NewFileRegistry(path)
	reg.RegisterIssuer("did:x", pub)
	reg.RemoveIssuer("did:x")

	if reg.IsTrusted("did:x") {
		t.Fatal("should not be trusted after removal")
	}

	// Verify file updated
	data, _ := os.ReadFile(path)
	if string(data) != "{}" {
		t.Fatalf("expected empty JSON object, got %s", string(data))
	}
}
