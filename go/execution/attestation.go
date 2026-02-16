// Package execution implements execution attestation types from APS v1.1 §20.
package execution

import "fmt"

// ExecutionAttestation captures a TEE/secure-enclave attestation for an agent execution.
type ExecutionAttestation struct {
	EnvelopeHash    string `json:"envelopeHash"`
	Measurement     string `json:"measurement"`
	Platform        string `json:"platform"`
	Nonce           string `json:"nonce"`
	ReportSignature string `json:"reportSignature"`
	TrustLevel      int    `json:"trustLevel"`
}

// Validate checks required fields and constraints.
func (a *ExecutionAttestation) Validate() error {
	if a.EnvelopeHash == "" {
		return fmt.Errorf("envelopeHash is required")
	}
	if a.Measurement == "" {
		return fmt.Errorf("measurement is required")
	}
	if a.Platform == "" {
		return fmt.Errorf("platform is required")
	}
	if a.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if a.ReportSignature == "" {
		return fmt.Errorf("reportSignature is required")
	}
	if a.TrustLevel < 0 || a.TrustLevel > 3 {
		return fmt.Errorf("trustLevel must be 0-3, got %d", a.TrustLevel)
	}
	return nil
}
