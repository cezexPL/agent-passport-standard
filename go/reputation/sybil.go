// Package reputation implements reputation scoring and sybil resistance types from APS v1.1 §21.
package reputation

import (
	"fmt"
	"time"
)

// IssuerWeight represents the trust weight of an attestation issuer (0-5).
type IssuerWeight int

const (
	IssuerWeightNone     IssuerWeight = 0
	IssuerWeightMinimal  IssuerWeight = 1
	IssuerWeightLow      IssuerWeight = 2
	IssuerWeightMedium   IssuerWeight = 3
	IssuerWeightHigh     IssuerWeight = 4
	IssuerWeightMaximum  IssuerWeight = 5
)

// ReputationScore holds the computed reputation with formula components.
type ReputationScore struct {
	AgentDID           string       `json:"agentDid"`
	Score              float64      `json:"score"`
	TaskSuccessRate    float64      `json:"taskSuccessRate"`
	AttestationCount   int          `json:"attestationCount"`
	UniqueIssuers      int          `json:"uniqueIssuers"`
	WeightedIssuerSum  float64      `json:"weightedIssuerSum"`
	AgeDecayFactor     float64      `json:"ageDecayFactor"`
	SybilPenalty       float64      `json:"sybilPenalty"`
	ComputedAt         time.Time    `json:"computedAt"`
}

// Validate checks the reputation score for consistency.
func (r *ReputationScore) Validate() error {
	if r.AgentDID == "" {
		return fmt.Errorf("agentDid is required")
	}
	if r.Score < 0 || r.Score > 1 {
		return fmt.Errorf("score must be 0-1, got %f", r.Score)
	}
	if r.TaskSuccessRate < 0 || r.TaskSuccessRate > 1 {
		return fmt.Errorf("taskSuccessRate must be 0-1, got %f", r.TaskSuccessRate)
	}
	if r.SybilPenalty < 0 || r.SybilPenalty > 1 {
		return fmt.Errorf("sybilPenalty must be 0-1, got %f", r.SybilPenalty)
	}
	return nil
}

// AnomalySignal represents a detected anomaly that may indicate sybil behavior.
type AnomalySignal struct {
	Type       string    `json:"type"`
	Severity   float64   `json:"severity"`
	DetectedAt time.Time `json:"detectedAt"`
	Evidence   string    `json:"evidence"`
	AgentDID   string    `json:"agentDid"`
}

// Validate checks required fields.
func (a *AnomalySignal) Validate() error {
	if a.Type == "" {
		return fmt.Errorf("type is required")
	}
	if a.AgentDID == "" {
		return fmt.Errorf("agentDid is required")
	}
	if a.Severity < 0 || a.Severity > 1 {
		return fmt.Errorf("severity must be 0-1, got %f", a.Severity)
	}
	return nil
}
