package aps_test

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/passport"
)

var sinkString string
var sinkBytes []byte
var sinkBool bool

func BenchmarkCanonicalizeJSON(b *testing.B) {
	obj := map[string]interface{}{
		"z_last": "value",
		"a_first": 42,
		"m_middle": []interface{}{"x", "y"},
		"nested": map[string]interface{}{"b": 2, "a": 1},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := crypto.CanonicalizeJSON(obj)
		sinkBytes = data
	}
}

func BenchmarkKeccak256(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString = crypto.Keccak256(data)
	}
}

func BenchmarkKeccak256Large(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString = crypto.Keccak256(data)
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, _ := crypto.GenerateKeyPair()
	data := []byte("benchmark signing payload")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString = crypto.Ed25519Sign(priv, data)
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	pub, priv, _ := crypto.GenerateKeyPair()
	data := []byte("benchmark verify payload")
	sig := crypto.Ed25519Sign(priv, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkBool, _ = crypto.Ed25519Verify(pub, data, sig)
	}
}

func BenchmarkPassportCreate(b *testing.B) {
	cfg := passport.Config{
		ID:        "did:key:z6MkBenchTest1234567890abcdefghijklmnop",
		PublicKey: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		OwnerDID:  "did:key:z6MkBenchOwner1234567890abcdefghijklmno",
		Skills: []passport.Skill{{
			Name: "go-backend", Version: "1.0.0",
			Description: "Go backend development", Capabilities: []string{"code_write"},
			Hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		}},
		Soul: passport.Soul{
			Personality: "Efficient", WorkStyle: "Systematic",
			Constraints: []string{"no-external-calls"},
			Hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		Policies: passport.Policies{
			PolicySetHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
			Summary:       []string{"read-only"},
		},
		Lineage: passport.Lineage{Kind: "original", Parents: []string{}, Generation: 0},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = passport.New(cfg)
	}
}

func BenchmarkPassportSignVerify(b *testing.B) {
	pub, priv, _ := crypto.GenerateKeyPair()
	cfg := passport.Config{
		ID:        "did:key:z6MkBenchTest1234567890abcdefghijklmnop",
		PublicKey: fmt.Sprintf("%x", pub),
		OwnerDID:  "did:key:z6MkBenchOwner1234567890abcdefghijklmno",
		Skills: []passport.Skill{{
			Name: "go-backend", Version: "1.0.0",
			Description: "Go backend development", Capabilities: []string{"code_write"},
			Hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		}},
		Soul: passport.Soul{
			Personality: "Efficient", WorkStyle: "Systematic",
			Constraints: []string{"no-external-calls"},
			Hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		Policies: passport.Policies{
			PolicySetHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
			Summary:       []string{"read-only"},
		},
		Lineage: passport.Lineage{Kind: "original", Parents: []string{}, Generation: 0},
	}
	p, _ := passport.New(cfg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Sign(priv)
		_, _ = p.Verify(ed25519.PublicKey(pub))
	}
}

func BenchmarkMerkleTree1000(b *testing.B) {
	leaves := make([]string, 1000)
	for i := range leaves {
		leaves[i] = crypto.Keccak256([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mt := crypto.NewMerkleTree(leaves)
		sinkString = mt.Root()
	}
}

func BenchmarkSnapshotHash(b *testing.B) {
	payload := map[string]interface{}{
		"skills":   map[string]interface{}{"entries": []interface{}{}, "frozen": false},
		"soul":     map[string]interface{}{"personality": "test", "hash": "0x00"},
		"policies": map[string]interface{}{"policy_set_hash": "0x00", "summary": []interface{}{}},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString, _ = crypto.SnapshotHash(payload)
	}
}
