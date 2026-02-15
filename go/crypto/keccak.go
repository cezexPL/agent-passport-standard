package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Keccak256 computes keccak-256 hash and returns "0x..." hex string.
func Keccak256(data []byte) string {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// Keccak256Bytes computes keccak-256 hash and returns raw 32 bytes.
func Keccak256Bytes(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SnapshotHash canonicalizes the payload and computes keccak256.
func SnapshotHash(payload interface{}) (string, error) {
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	return Keccak256(canonical), nil
}

// HashExcludingFields marshals v to JSON, removes specified top-level keys, canonicalizes, and computes keccak256.
func HashExcludingFields(v interface{}, exclude ...string) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("not an object: %w", err)
	}

	for _, key := range exclude {
		delete(m, key)
	}

	canonical, err := CanonicalizeJSON(m)
	if err != nil {
		return "", err
	}
	return Keccak256(canonical), nil
}
