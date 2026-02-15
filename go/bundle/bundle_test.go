package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cezexPL/agent-passport-standard/go/attestation"
	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/passport"
	"github.com/cezexPL/agent-passport-standard/go/receipt"
)

func makeTestPassport(t *testing.T, privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *passport.AgentPassport {
	t.Helper()
	p, err := passport.New(passport.Config{
		ID:        "did:key:test-agent-001",
		PublicKey: hex.EncodeToString(pubKey),
		OwnerDID:  "did:web:example.com",
		Skills: []passport.Skill{
			{
				Name:         "code-review",
				Version:      "1.0.0",
				Description:  "Reviews code",
				Capabilities: []string{"go", "python"},
				Hash:         "0xabc",
			},
		},
		Soul: passport.Soul{
			Personality: "helpful",
			WorkStyle:   "thorough",
			Constraints: []string{"no-harmful-code"},
			Hash:        "0xdef",
		},
		Policies: passport.Policies{
			PolicySetHash: "0x123",
			Summary:       []string{"safe"},
		},
		Lineage: passport.Lineage{
			Kind:       "original",
			Parents:    []string{},
			Generation: 0,
		},
	})
	if err != nil {
		t.Fatalf("create passport: %v", err)
	}
	if err := p.Sign(privKey); err != nil {
		t.Fatalf("sign passport: %v", err)
	}
	return p
}

func makeTestReceipt(t *testing.T, privKey ed25519.PrivateKey) receipt.WorkReceipt {
	t.Helper()
	r, err := receipt.New(receipt.Config{
		ReceiptID:     "receipt-001",
		JobID:         "job-001",
		AgentDID:      "did:key:test-agent-001",
		ClientDID:     "did:web:client.com",
		AgentSnapshot: receipt.AgentSnapshot{Version: 1, Hash: "0xabc"},
	})
	if err != nil {
		t.Fatalf("create receipt: %v", err)
	}
	_ = r.AddEvent(receipt.ReceiptEvent{Type: "claim", Timestamp: "2025-01-01T00:00:00Z"})
	_ = r.AddEvent(receipt.ReceiptEvent{Type: "submit", Timestamp: "2025-01-02T00:00:00Z"})
	if err := r.Sign(privKey); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return *r
}

func makeTestAttestation(t *testing.T, privKey ed25519.PrivateKey) attestation.Attestation {
	t.Helper()
	att, err := attestation.CreateAttestation(
		"did:key:test-agent-001",
		"did:key:test-agent-001",
		"SkillVerification",
		map[string]interface{}{"skill": "go", "level": "expert"},
		privKey,
	)
	if err != nil {
		t.Fatalf("create attestation: %v", err)
	}
	return *att
}

func TestNewBundle(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p)
	if b.Context != "https://agentpassport.org/v0.2/bundle" {
		t.Errorf("unexpected context: %s", b.Context)
	}
	if b.Type != "AgentPassportBundle" {
		t.Errorf("unexpected type: %s", b.Type)
	}
	if b.Version != "1.0.0" {
		t.Errorf("unexpected version: %s", b.Version)
	}
	if b.Passport != p {
		t.Error("passport not set")
	}
}

func TestNewBundleWithOptions(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)
	r := makeTestReceipt(t, priv)
	att := makeTestAttestation(t, priv)

	rep := ReputationSummary{
		AgentID:       "did:key:test-agent-001",
		Platform:      "clawbotden",
		Period:        Period{From: "2025-01-01", To: "2025-06-01"},
		JobsCompleted: 42,
		JobsVerified:  40,
		AvgQuality:    0.95,
		AvgTimeliness: 0.90,
		TrustTier:     3,
		ComputedAt:    "2025-06-01T00:00:00Z",
	}

	b := NewBundle(p,
		WithReceipts([]receipt.WorkReceipt{r}),
		WithAttestations([]attestation.Attestation{att}),
		WithReputation(rep),
		WithPlatformDID("did:web:clawbotden.com"),
	)

	if len(b.WorkReceipts) != 1 {
		t.Errorf("expected 1 receipt, got %d", len(b.WorkReceipts))
	}
	if len(b.Attestations) != 1 {
		t.Errorf("expected 1 attestation, got %d", len(b.Attestations))
	}
	if b.Reputation == nil {
		t.Error("reputation not set")
	}
	if b.ExportedFrom != "did:web:clawbotden.com" {
		t.Errorf("unexpected exported_from: %s", b.ExportedFrom)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p, WithPlatformDID("did:web:test.com"))
	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if b.Proof == nil {
		t.Fatal("proof is nil after signing")
	}
	if b.Proof.Type != "Ed25519Signature2020" {
		t.Errorf("unexpected proof type: %s", b.Proof.Type)
	}

	valid, err := b.Verify(pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestTamperDetection(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p, WithPlatformDID("did:web:test.com"))
	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper with exported_from
	b.ExportedFrom = "did:web:evil.com"

	valid, err := b.Verify(pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if valid {
		t.Error("expected invalid signature after tampering")
	}
}

func TestVerifyWithWrongKey(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	pub2, _, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p)
	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	valid, err := b.Verify(pub2)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if valid {
		t.Error("expected invalid with wrong key")
	}
}

func TestVerifyNoProof(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)
	b := NewBundle(p)

	_, err := b.Verify(pub)
	if err == nil {
		t.Error("expected error for missing proof")
	}
}

func TestVerifyAll(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)
	r := makeTestReceipt(t, priv)
	att := makeTestAttestation(t, priv)

	b := NewBundle(p,
		WithReceipts([]receipt.WorkReceipt{r}),
		WithAttestations([]attestation.Attestation{att}),
	)
	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	report, err := b.VerifyAll(pub)
	if err != nil {
		t.Fatalf("verify all: %v", err)
	}

	if !report.BundleValid {
		t.Errorf("bundle should be valid, errors: %v", report.Errors)
	}
	if !report.PassportValid {
		t.Errorf("passport should be valid, errors: %v", report.Errors)
	}
	if len(report.ReceiptsValid) != 1 || !report.ReceiptsValid[0] {
		t.Errorf("receipt should be valid, errors: %v", report.Errors)
	}
	if len(report.AttestationsValid) != 1 || !report.AttestationsValid[0] {
		t.Errorf("attestation should be valid, errors: %v", report.Errors)
	}
}

func TestJSONRoundtrip(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)
	r := makeTestReceipt(t, priv)

	b := NewBundle(p,
		WithReceipts([]receipt.WorkReceipt{r}),
		WithPlatformDID("did:web:test.com"),
	)
	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	data, err := b.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}

	b2, err := FromJSON(data)
	if err != nil {
		t.Fatalf("from json: %v", err)
	}

	if b2.Context != b.Context {
		t.Errorf("context mismatch: %s vs %s", b2.Context, b.Context)
	}
	if b2.Type != b.Type {
		t.Errorf("type mismatch")
	}
	if b2.ExportedFrom != b.ExportedFrom {
		t.Errorf("exported_from mismatch")
	}
	if b2.Passport.ID != b.Passport.ID {
		t.Errorf("passport ID mismatch")
	}
	if len(b2.WorkReceipts) != 1 {
		t.Errorf("expected 1 receipt, got %d", len(b2.WorkReceipts))
	}
	if b2.Proof == nil || b2.Proof.ProofValue != b.Proof.ProofValue {
		t.Error("proof mismatch")
	}

	// Verify the deserialized bundle
	valid, err := b2.Verify(pub)
	if err != nil {
		t.Fatalf("verify roundtrip: %v", err)
	}
	if !valid {
		t.Error("roundtrip verification failed")
	}
}

func TestEmptyBundle(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p)
	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if len(b.WorkReceipts) != 0 {
		t.Errorf("expected no receipts")
	}
	if len(b.Attestations) != 0 {
		t.Errorf("expected no attestations")
	}
	if b.Reputation != nil {
		t.Errorf("expected no reputation")
	}

	valid, err := b.Verify(pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Error("empty bundle should be valid")
	}
}

func TestHash(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p)
	h1, err := b.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h1[:2] != "0x" {
		t.Errorf("expected 0x prefix, got %s", h1[:2])
	}

	// Hash should be stable
	h2, _ := b.Hash()
	if h1 != h2 {
		t.Error("hash not stable")
	}

	// Hash should change after modification
	b.ExportedFrom = "did:web:changed.com"
	h3, _ := b.Hash()
	if h1 == h3 {
		t.Error("hash should change after modification")
	}
}

func TestHashExcludesProof(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)

	b := NewBundle(p)
	h1, _ := b.Hash()

	if err := b.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	h2, _ := b.Hash()
	if h1 != h2 {
		t.Error("hash should not change after signing (proof excluded)")
	}
}

func TestFromJSONInvalid(t *testing.T) {
	_, err := FromJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestJSONCanonical(t *testing.T) {
	pub, priv, _ := crypto.GenerateKeyPair()
	p := makeTestPassport(t, priv, pub)
	b := NewBundle(p)

	data, err := b.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}

	// Should be valid JSON
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	// Should have @context as first key concept (canonical = sorted)
	if _, ok := m["@context"]; !ok {
		t.Error("missing @context")
	}
}
