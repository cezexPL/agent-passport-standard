package provenance

import (
	"encoding/json"
	"testing"
)

func sampleProvenance() Provenance {
	return Provenance{
		ModelDigest:        "sha256:model123",
		ToolchainDigest:    "sha256:tc456",
		PromptTemplateHash: "sha256:pt789",
		PolicyHash:         "sha256:pol000",
		RuntimeVersion:     "1.2.3",
		ParentReceiptIDs:   []string{"receipt-1", "receipt-2"},
		PipelineID:         "pipeline-abc",
		StepIndex:          2,
		Watermark:          "wm-xyz",
	}
}

func TestProvenanceRoundTrip(t *testing.T) {
	p := sampleProvenance()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p2 Provenance
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p2.ModelDigest != p.ModelDigest {
		t.Errorf("modelDigest mismatch")
	}
	if p2.StepIndex != 2 {
		t.Errorf("stepIndex: got %d, want 2", p2.StepIndex)
	}
}

func TestProvenanceValidate(t *testing.T) {
	p := sampleProvenance()
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	bad := Provenance{}
	if err := bad.Validate(); err == nil {
		t.Error("expected error")
	}
}
