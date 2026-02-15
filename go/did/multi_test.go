package did

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestMultiResolverDispatch(t *testing.T) {
	mr := DefaultResolver()

	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	multicodec := append([]byte{0xed, 0x01}, pub...)
	didKey := "did:key:z" + EncodeBase58BTC(multicodec)

	t.Run("dispatches to did:key", func(t *testing.T) {
		doc, err := mr.Resolve(didKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if doc.ID != didKey {
			t.Errorf("ID mismatch")
		}
	})

	t.Run("unsupported method", func(t *testing.T) {
		_, err := mr.Resolve("did:example:123")
		if err == nil {
			t.Error("expected error for unsupported method")
		}
	})

	t.Run("invalid DID", func(t *testing.T) {
		_, err := mr.Resolve("garbage")
		if err == nil {
			t.Error("expected error for invalid DID")
		}
	})
}

func TestParseDID(t *testing.T) {
	tests := []struct {
		did        string
		wantMethod string
		wantSpec   string
		wantErr    bool
	}{
		{"did:key:z6Mk123", "key", "z6Mk123", false},
		{"did:web:example.com", "web", "example.com", false},
		{"did:web:example.com:path:to", "web", "example.com:path:to", false},
		{"not-a-did", "", "", true},
		{"did:", "", "", true},
		{"did::", "", "", true},
	}
	for _, tt := range tests {
		m, s, err := ParseDID(tt.did)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseDID(%s) error = %v, wantErr %v", tt.did, err, tt.wantErr)
			continue
		}
		if m != tt.wantMethod || s != tt.wantSpec {
			t.Errorf("ParseDID(%s) = (%s, %s), want (%s, %s)", tt.did, m, s, tt.wantMethod, tt.wantSpec)
		}
	}
}
