package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// Ed25519Sign signs data with the given Ed25519 private key, returning the hex-encoded signature.
func Ed25519Sign(privateKey ed25519.PrivateKey, data []byte) string {
	sig := ed25519.Sign(privateKey, data)
	return hex.EncodeToString(sig)
}

// Ed25519Verify verifies an Ed25519 signature (hex-encoded) against the given public key and data.
func Ed25519Verify(publicKey ed25519.PublicKey, data []byte, signatureHex string) (bool, error) {
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(publicKey, data, sig), nil
}

// GenerateKeyPair generates a new Ed25519 key pair for testing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	return pub, priv, nil
}
