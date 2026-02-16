package execution

import (
	"encoding/json"
	"testing"
)

func sampleAttestation() ExecutionAttestation {
	return ExecutionAttestation{
		EnvelopeHash:    "sha256:env",
		Measurement:     "sha256:meas",
		Platform:        "sgx",
		Nonce:           "nonce123",
		ReportSignature: "sig456",
		TrustLevel:      2,
	}
}

func TestExecutionAttestationRoundTrip(t *testing.T) {
	a := sampleAttestation()
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var a2 ExecutionAttestation
	if err := json.Unmarshal(data, &a2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a2.Platform != "sgx" || a2.TrustLevel != 2 {
		t.Error("mismatch")
	}
}

func TestExecutionAttestationValidate(t *testing.T) {
	a := sampleAttestation()
	if err := a.Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	// bad trust level
	bad := sampleAttestation()
	bad.TrustLevel = 5
	if err := bad.Validate(); err == nil {
		t.Error("expected error for trustLevel=5")
	}

	// missing field
	bad2 := ExecutionAttestation{}
	if err := bad2.Validate(); err == nil {
		t.Error("expected error")
	}
}
