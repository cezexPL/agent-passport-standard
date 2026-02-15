package crypto

import (
	"testing"
)

func TestEd25519SignVerify(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello agent passport")
	sig := Ed25519Sign(priv, msg)
	ok, err := Ed25519Verify(pub, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("signature should be valid")
	}
}

func TestEd25519Verify_WrongKey(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()
	msg := []byte("test")
	sig := Ed25519Sign(priv, msg)
	ok, err := Ed25519Verify(pub2, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("should not verify with wrong key")
	}
}

func TestEd25519Verify_WrongMessage(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sig := Ed25519Sign(priv, []byte("original"))
	ok, err := Ed25519Verify(pub, []byte("tampered"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("should not verify with wrong message")
	}
}

func TestEd25519_SignatureLength(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	sig := Ed25519Sign(priv, []byte("test message"))
	// Ed25519 signatures are 64 bytes = 128 hex chars
	if len(sig) != 128 {
		t.Errorf("signature hex length = %d, want 128", len(sig))
	}
}

func TestEd25519_InvalidSignatureHex(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	_, err := Ed25519Verify(pub, []byte("test"), "not-hex")
	if err == nil {
		t.Error("should fail on invalid hex")
	}
}
