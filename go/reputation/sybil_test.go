package reputation

import (
	"encoding/json"
	"testing"
	"time"
)

func TestReputationScoreRoundTrip(t *testing.T) {
	r := ReputationScore{
		AgentDID:          "did:key:z123",
		Score:             0.85,
		TaskSuccessRate:   0.92,
		AttestationCount:  15,
		UniqueIssuers:     5,
		WeightedIssuerSum: 18.5,
		AgeDecayFactor:    0.95,
		SybilPenalty:      0.02,
		ComputedAt:        time.Now().UTC().Truncate(time.Millisecond),
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var r2 ReputationScore
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r2.Score != r.Score || r2.AgentDID != r.AgentDID {
		t.Error("mismatch")
	}
}

func TestReputationScoreValidate(t *testing.T) {
	good := ReputationScore{AgentDID: "did:key:z1", Score: 0.5, TaskSuccessRate: 0.5}
	if err := good.Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	bad := ReputationScore{Score: 1.5}
	if err := bad.Validate(); err == nil {
		t.Error("expected error")
	}
}

func TestIssuerWeightConstants(t *testing.T) {
	if IssuerWeightNone != 0 || IssuerWeightMaximum != 5 {
		t.Error("issuer weight constants wrong")
	}
}

func TestAnomalySignalRoundTrip(t *testing.T) {
	a := AnomalySignal{
		Type:       "velocity-spike",
		Severity:   0.8,
		DetectedAt: time.Now().UTC().Truncate(time.Millisecond),
		Evidence:   "50 tasks in 1 minute",
		AgentDID:   "did:key:z1",
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var a2 AnomalySignal
	if err := json.Unmarshal(data, &a2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a2.Type != a.Type {
		t.Error("type mismatch")
	}
}

func TestAnomalySignalValidate(t *testing.T) {
	bad := AnomalySignal{Severity: 2.0}
	if err := bad.Validate(); err == nil {
		t.Error("expected error")
	}
}
