package attestation

import (
	"testing"
	"time"

	apscrypto "github.com/cezexPL/agent-passport-standard/go/crypto"
)

func TestCreateAndVerifyAttestation(t *testing.T) {
	pub, priv, err := apscrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	att, err := CreateAttestation(
		"did:key:z6MkIssuer",
		"did:key:z6MkSubject",
		"SkillVerification",
		map[string]interface{}{"skill": "go-backend", "level": "expert"},
		priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	if att.Issuer != "did:key:z6MkIssuer" {
		t.Errorf("unexpected issuer: %s", att.Issuer)
	}
	if att.Subject.ID != "did:key:z6MkSubject" {
		t.Errorf("unexpected subject: %s", att.Subject.ID)
	}

	valid, err := VerifyAttestation(att, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected valid attestation")
	}
}

func TestRejectTamperedAttestation(t *testing.T) {
	pub, priv, _ := apscrypto.GenerateKeyPair()

	att, _ := CreateAttestation(
		"did:key:z6MkIssuer",
		"did:key:z6MkSubject",
		"SkillVerification",
		map[string]interface{}{"skill": "go-backend"},
		priv,
	)

	// Tamper
	att.Subject.Claims["skill"] = "hacking"

	valid, err := VerifyAttestation(att, pub)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected invalid attestation after tampering")
	}
}

func TestRejectExpiredAttestation(t *testing.T) {
	pub, priv, _ := apscrypto.GenerateKeyPair()

	expired := time.Now().UTC().Add(-1 * time.Hour)
	att, _ := CreateAttestationWithExpiry(
		"did:key:z6MkIssuer",
		"did:key:z6MkSubject",
		"SkillVerification",
		map[string]interface{}{"skill": "go-backend"},
		priv,
		expired,
	)

	valid, err := VerifyAttestation(att, pub)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected invalid attestation (expired)")
	}
}

func TestRejectWrongKey(t *testing.T) {
	_, priv, _ := apscrypto.GenerateKeyPair()
	otherPub, _, _ := apscrypto.GenerateKeyPair()

	att, _ := CreateAttestation(
		"did:key:z6MkIssuer",
		"did:key:z6MkSubject",
		"SkillVerification",
		map[string]interface{}{"skill": "go-backend"},
		priv,
	)

	valid, err := VerifyAttestation(att, otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected invalid attestation with wrong key")
	}
}

func TestAttestationRegistry(t *testing.T) {
	pub, priv, _ := apscrypto.GenerateKeyPair()

	registry := NewAttestationRegistry()
	registry.RegisterIssuer("did:key:z6MkIssuer", pub)

	if !registry.IsTrusted("did:key:z6MkIssuer") {
		t.Error("expected issuer to be trusted")
	}
	if registry.IsTrusted("did:key:z6MkUnknown") {
		t.Error("expected unknown issuer to not be trusted")
	}

	att, _ := CreateAttestation(
		"did:key:z6MkIssuer",
		"did:key:z6MkSubject",
		"SkillVerification",
		map[string]interface{}{"skill": "go-backend"},
		priv,
	)

	valid, err := registry.VerifyFromRegistry(att)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected valid attestation from registry")
	}

	// Untrusted issuer
	att2, _ := CreateAttestation(
		"did:key:z6MkUntrusted",
		"did:key:z6MkSubject",
		"SkillVerification",
		map[string]interface{}{},
		priv,
	)

	_, err = registry.VerifyFromRegistry(att2)
	if err == nil {
		t.Error("expected error for untrusted issuer")
	}
}
