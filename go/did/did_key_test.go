package did

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestDIDKeyResolve(t *testing.T) {
	// Generate a known key pair
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Build did:key: multicodec(0xed01) + pubkey, base58btc with 'z' prefix
	multicodec := append([]byte{0xed, 0x01}, pub...)
	didStr := "did:key:z" + EncodeBase58BTC(multicodec)

	resolver := NewDIDKeyResolver()

	t.Run("resolve valid did:key", func(t *testing.T) {
		doc, err := resolver.Resolve(didStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if doc.ID != didStr {
			t.Errorf("ID = %s, want %s", doc.ID, didStr)
		}
		if len(doc.VerificationMethod) != 1 {
			t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
		}
		if doc.VerificationMethod[0].Type != "Ed25519VerificationKey2020" {
			t.Errorf("unexpected type: %s", doc.VerificationMethod[0].Type)
		}
	})

	t.Run("extract public key", func(t *testing.T) {
		doc, _ := resolver.Resolve(didStr)
		extracted, err := ExtractPublicKey(doc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !pub.Equal(extracted) {
			t.Error("extracted key does not match original")
		}
	})

	t.Run("invalid DID", func(t *testing.T) {
		_, err := resolver.Resolve("not-a-did")
		if err == nil {
			t.Error("expected error for invalid DID")
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		_, err := resolver.Resolve("did:web:example.com")
		if err == nil {
			t.Error("expected error for wrong method")
		}
	})

	t.Run("invalid multibase prefix", func(t *testing.T) {
		_, err := resolver.Resolve("did:key:abc123")
		if err == nil {
			t.Error("expected error for missing z prefix")
		}
	})
}

// Known test vector from did:key spec
func TestDIDKeyKnownVector(t *testing.T) {
	// did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	resolver := NewDIDKeyResolver()
	doc, err := resolver.Resolve(did)
	if err != nil {
		t.Fatalf("failed to resolve known vector: %v", err)
	}
	if doc.ID != did {
		t.Errorf("ID mismatch")
	}
	key, err := ExtractPublicKey(doc)
	if err != nil {
		t.Fatalf("failed to extract key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}
