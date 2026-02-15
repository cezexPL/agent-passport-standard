package crypto

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// --- Timing-Safe Comparison Tests ---

func TestTimingSafeEqual_Match(t *testing.T) {
	a := "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	if !TimingSafeEqual(a, a) {
		t.Error("identical strings should be equal")
	}
}

func TestTimingSafeEqual_Mismatch(t *testing.T) {
	a := "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	b := "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567891"
	if TimingSafeEqual(a, b) {
		t.Error("different strings should not be equal")
	}
}

func TestTimingSafeEqual_DifferentLengths(t *testing.T) {
	if TimingSafeEqual("short", "longer string") {
		t.Error("different length strings should not be equal")
	}
}

// --- Validation Tests ---

func TestValidateDID_Valid(t *testing.T) {
	if err := ValidateDID("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"); err != nil {
		t.Errorf("valid DID rejected: %v", err)
	}
}

func TestValidateDID_Empty(t *testing.T) {
	if err := ValidateDID(""); err == nil {
		t.Error("empty DID should fail")
	}
}

func TestValidateDID_Invalid(t *testing.T) {
	invalids := []string{"not-a-did", "did:key:abc", "did:web:example.com", "did:key:z6Mk"}
	for _, d := range invalids {
		if err := ValidateDID(d); err == nil {
			t.Errorf("invalid DID %q should fail", d)
		}
	}
}

func TestValidateHash_Valid(t *testing.T) {
	if err := ValidateHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"); err != nil {
		t.Errorf("valid hash rejected: %v", err)
	}
}

func TestValidateHash_Invalid(t *testing.T) {
	invalids := []string{"", "abcdef", "0x123", "0xGGGG567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}
	for _, h := range invalids {
		if err := ValidateHash(h); err == nil {
			t.Errorf("invalid hash %q should fail", h)
		}
	}
}

func TestValidateSignature_Valid(t *testing.T) {
	sig := strings.Repeat("ab", 64)
	if err := ValidateSignature(sig); err != nil {
		t.Errorf("valid sig rejected: %v", err)
	}
}

func TestValidateSignature_Invalid(t *testing.T) {
	if err := ValidateSignature(""); err == nil {
		t.Error("empty sig should fail")
	}
	if err := ValidateSignature("tooshort"); err == nil {
		t.Error("short sig should fail")
	}
}

func TestValidateTimestamp_Valid(t *testing.T) {
	if err := ValidateTimestamp("2026-02-15T12:00:00Z"); err != nil {
		t.Errorf("valid timestamp rejected: %v", err)
	}
}

func TestValidateTimestamp_Invalid(t *testing.T) {
	if err := ValidateTimestamp(""); err == nil {
		t.Error("empty timestamp should fail")
	}
	if err := ValidateTimestamp("not-a-date"); err == nil {
		t.Error("invalid timestamp should fail")
	}
}

func TestValidateVersion_Valid(t *testing.T) {
	if err := ValidateVersion(1); err != nil {
		t.Error("version 1 should be valid")
	}
}

func TestValidateVersion_Invalid(t *testing.T) {
	if err := ValidateVersion(0); err == nil {
		t.Error("version 0 should fail")
	}
	if err := ValidateVersion(-1); err == nil {
		t.Error("negative version should fail")
	}
}

func TestValidateTrustTier_Valid(t *testing.T) {
	for i := 0; i <= 3; i++ {
		if err := ValidateTrustTier(i); err != nil {
			t.Errorf("tier %d should be valid", i)
		}
	}
}

func TestValidateTrustTier_Invalid(t *testing.T) {
	if err := ValidateTrustTier(-1); err == nil {
		t.Error("tier -1 should fail")
	}
	if err := ValidateTrustTier(4); err == nil {
		t.Error("tier 4 should fail")
	}
	if err := ValidateTrustTier(999); err == nil {
		t.Error("tier 999 should fail")
	}
}

func TestValidateAttestationCount_Invalid(t *testing.T) {
	if err := ValidateAttestationCount(-1); err == nil {
		t.Error("negative attestation count should fail")
	}
}

// --- Signature Forgery ---

func TestSignatureForgery(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	data := []byte("original passport data")
	sig := Ed25519Sign(priv, data)

	// Tamper with data
	tampered := []byte("tampered passport data")
	ok, _ := Ed25519Verify(pub, tampered, sig)
	if ok {
		t.Error("tampered data should not verify")
	}
}

// --- Hash Manipulation ---

func TestHashManipulation(t *testing.T) {
	payload1 := map[string]interface{}{"skill": "go", "version": 1}
	payload2 := map[string]interface{}{"skill": "go", "version": 2}
	h1, _ := SnapshotHash(payload1)
	h2, _ := SnapshotHash(payload2)
	if h1 == h2 {
		t.Error("different payloads should produce different hashes")
	}
}

// --- Replay Attack ---

func TestReplayAttack(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	data1 := []byte("passport-1-data")
	sig := Ed25519Sign(priv, data1)

	data2 := []byte("passport-2-data")
	ok, _ := Ed25519Verify(pub, data2, sig)
	if ok {
		t.Error("signature from one document should not verify on another")
	}
	// Same key, same sig, correct data should still work
	ok, _ = Ed25519Verify(pub, data1, sig)
	if !ok {
		t.Error("original should still verify")
	}
}

// --- Key Mismatch ---

func TestKeyMismatch(t *testing.T) {
	_, privA, _ := GenerateKeyPair()
	pubB, _, _ := GenerateKeyPair()
	data := []byte("test data")
	sig := Ed25519Sign(privA, data)
	ok, _ := Ed25519Verify(pubB, data, sig)
	if ok {
		t.Error("wrong key should not verify")
	}
}

// --- Oversized Input ---

func TestOversizedInput(t *testing.T) {
	skills := make([]interface{}, 10000)
	for i := range skills {
		skills[i] = fmt.Sprintf("skill-%d", i)
	}
	payload := map[string]interface{}{"skills": skills}
	h, err := SnapshotHash(payload)
	if err != nil {
		t.Fatalf("oversized input should not crash: %v", err)
	}
	if h == "" {
		t.Error("hash should not be empty")
	}
}

// --- Unicode Edge Cases ---

func TestUnicodeEdgeCases(t *testing.T) {
	cases := []map[string]interface{}{
		{"skill": "🤖"},
		{"skill": "مرحبا"},
		{"skill": "a\x00b"},
		{"skill": "emoji 🎯 test"},
	}
	for _, c := range cases {
		h, err := SnapshotHash(c)
		if err != nil {
			t.Fatalf("unicode case failed: %v", err)
		}
		if h == "" {
			t.Error("hash should not be empty for unicode input")
		}
	}
}

// --- Integer Overflow ---

func TestIntegerOverflow(t *testing.T) {
	if err := ValidateVersion(math.MaxInt64); err != nil {
		t.Error("max int version should be valid")
	}
	if err := ValidateTrustTier(999); err == nil {
		t.Error("tier 999 should be invalid")
	}
	if err := ValidateAttestationCount(-1); err == nil {
		t.Error("negative attestation should be invalid")
	}
}

// --- Canonical JSON Edge Cases ---

func TestCanonicalJSON_NullTrueFalse(t *testing.T) {
	input := map[string]interface{}{
		"a": nil,
		"b": true,
		"c": false,
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":null,"b":true,"c":false}`
	if string(result) != expected {
		t.Errorf("got %s, want %s", string(result), expected)
	}
}

func TestCanonicalJSON_NestedUnsortedKeys(t *testing.T) {
	input := map[string]interface{}{
		"z": map[string]interface{}{
			"b": 2,
			"a": 1,
		},
		"a": "first",
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":"first","z":{"a":1,"b":2}}`
	if string(result) != expected {
		t.Errorf("got %s, want %s", string(result), expected)
	}
}

func TestCanonicalJSON_MixedArray(t *testing.T) {
	input := []interface{}{1, "two", true, nil, map[string]interface{}{"b": 2, "a": 1}}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `[1,"two",true,null,{"a":1,"b":2}]`
	if string(result) != expected {
		t.Errorf("got %s, want %s", string(result), expected)
	}
}

func TestCanonicalJSON_SpecialChars(t *testing.T) {
	input := map[string]interface{}{
		"quote":     `a"b`,
		"backslash": `a\b`,
		"newline":   "a\nb",
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	// Just verify it doesn't crash and is deterministic
	result2, _ := CanonicalizeJSON(input)
	if string(result) != string(result2) {
		t.Error("not deterministic for special chars")
	}
}

func TestCanonicalJSON_Numbers(t *testing.T) {
	input := map[string]interface{}{
		"zero":     0,
		"one":      1,
		"negative": -1,
		"float":    1.5,
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) == "" {
		t.Error("should not be empty")
	}
}

// --- Merkle Proof with Timing-Safe Comparison ---

func TestMerkleVerifyProof_TimingSafe(t *testing.T) {
	leaves := make([]string, 4)
	for i := range leaves {
		leaves[i] = Keccak256([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	tree := NewMerkleTree(leaves)
	root := tree.Root()
	proof := tree.Proof(0)

	// Correct verification
	if !VerifyProof(leaves[0], root, proof, 0) {
		t.Error("valid proof should verify")
	}

	// Wrong root (timing-safe comparison should still reject)
	fakeRoot := "0x0000000000000000000000000000000000000000000000000000000000000000"
	if VerifyProof(leaves[0], fakeRoot, proof, 0) {
		t.Error("wrong root should not verify")
	}
}
