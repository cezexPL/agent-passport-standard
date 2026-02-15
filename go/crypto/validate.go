package crypto

import (
	"crypto/subtle"
	"fmt"
	"regexp"
	"time"
)

var (
	didPattern  = regexp.MustCompile(`^did:key:z6Mk[A-Za-z0-9]+$`)
	hashPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	sigPattern  = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)
)

// TimingSafeEqual compares two hex strings in constant time.
func TimingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateDID checks that s matches did:key:z6Mk... pattern.
func ValidateDID(s string) error {
	if s == "" {
		return fmt.Errorf("DID must not be empty")
	}
	if !didPattern.MatchString(s) {
		return fmt.Errorf("invalid DID format: %s", s)
	}
	return nil
}

// ValidateHash checks 0x + 64 hex chars.
func ValidateHash(s string) error {
	if s == "" {
		return fmt.Errorf("hash must not be empty")
	}
	if !hashPattern.MatchString(s) {
		return fmt.Errorf("invalid hash format: %s", s)
	}
	return nil
}

// ValidateSignature checks 128 hex chars (Ed25519).
func ValidateSignature(s string) error {
	if s == "" {
		return fmt.Errorf("signature must not be empty")
	}
	if !sigPattern.MatchString(s) {
		return fmt.Errorf("invalid signature format: %s", s)
	}
	return nil
}

// ValidateTimestamp checks ISO 8601 / RFC 3339.
func ValidateTimestamp(s string) error {
	if s == "" {
		return fmt.Errorf("timestamp must not be empty")
	}
	_, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %s", s)
	}
	return nil
}

// ValidateVersion checks positive integer.
func ValidateVersion(v int) error {
	if v < 1 {
		return fmt.Errorf("version must be positive, got %d", v)
	}
	return nil
}

// ValidateTrustTier checks 0-3.
func ValidateTrustTier(t int) error {
	if t < 0 || t > 3 {
		return fmt.Errorf("trust tier must be 0-3, got %d", t)
	}
	return nil
}

// ValidateAttestationCount checks non-negative.
func ValidateAttestationCount(c int) error {
	if c < 0 {
		return fmt.Errorf("attestation count must be non-negative, got %d", c)
	}
	return nil
}
