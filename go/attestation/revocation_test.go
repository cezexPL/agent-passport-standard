package attestation

import (
	"testing"

	apscrypto "github.com/cezexPL/agent-passport-standard/go/crypto"
)

func TestRevocationList_RevokeAndCheck(t *testing.T) {
	rl := NewRevocationList("did:web:issuer")

	hash := "0xabc123"
	if rl.IsRevoked(hash) {
		t.Fatal("should not be revoked yet")
	}

	rl.Revoke(hash)
	if !rl.IsRevoked(hash) {
		t.Fatal("should be revoked")
	}

	// Duplicate revoke is idempotent
	rl.Revoke(hash)
	if len(rl.Revoked) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(rl.Revoked))
	}
}

func TestRevocationList_SignAndVerify(t *testing.T) {
	pub, priv, _ := apscrypto.GenerateKeyPair()

	rl := NewRevocationList("did:web:issuer")
	rl.Revoke("0xdeadbeef")

	if err := rl.Sign(priv); err != nil {
		t.Fatal(err)
	}

	ok, err := rl.Verify(pub)
	if err != nil || !ok {
		t.Fatalf("expected valid, got ok=%v err=%v", ok, err)
	}

	// Tamper
	rl.Revoked = append(rl.Revoked, "0xtampered")
	ok, err = rl.Verify(pub)
	if err != nil || ok {
		t.Fatal("expected invalid after tampering")
	}
}

func TestRevocationList_JSONRoundtrip(t *testing.T) {
	pub, priv, _ := apscrypto.GenerateKeyPair()

	rl := NewRevocationList("did:web:issuer")
	rl.Revoke("0xaaa")
	rl.Sign(priv)

	data, err := rl.JSON()
	if err != nil {
		t.Fatal(err)
	}

	rl2, err := RevocationListFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := rl2.Verify(pub)
	if err != nil || !ok {
		t.Fatalf("roundtrip verify failed: ok=%v err=%v", ok, err)
	}
}

func TestCheckRevocation(t *testing.T) {
	_, priv, _ := apscrypto.GenerateKeyPair()
	issuerDID := "did:web:issuer"

	att, err := CreateAttestation(issuerDID, "did:web:subject", "identity", map[string]interface{}{"ok": true}, priv)
	if err != nil {
		t.Fatal(err)
	}

	rl := NewRevocationList(issuerDID)

	// Not revoked
	ok, err := CheckRevocation(att, rl)
	if err != nil || !ok {
		t.Fatalf("expected not revoked, got ok=%v err=%v", ok, err)
	}

	// Compute hash and revoke
	hash, err := apscrypto.HashExcludingFields(att, "proof")
	if err != nil {
		t.Fatal(err)
	}
	rl.Revoke(hash)

	ok, err = CheckRevocation(att, rl)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected revoked")
	}
}
