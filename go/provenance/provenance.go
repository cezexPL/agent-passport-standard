// Package provenance implements artifact provenance types from APS v1.1 §18.
package provenance

import "fmt"

// Provenance captures the full build/inference provenance of an agent output.
type Provenance struct {
	ModelDigest        string   `json:"modelDigest"`
	ToolchainDigest    string   `json:"toolchainDigest"`
	PromptTemplateHash string   `json:"promptTemplateHash"`
	PolicyHash         string   `json:"policyHash"`
	RuntimeVersion     string   `json:"runtimeVersion"`
	ParentReceiptIDs   []string `json:"parentReceiptIds"`
	PipelineID         string   `json:"pipelineId"`
	StepIndex          int      `json:"stepIndex"`
	Watermark          string   `json:"watermark,omitempty"`
}

// Validate checks required fields.
func (p *Provenance) Validate() error {
	if p.ModelDigest == "" {
		return fmt.Errorf("modelDigest is required")
	}
	if p.ToolchainDigest == "" {
		return fmt.Errorf("toolchainDigest is required")
	}
	if p.PipelineID == "" {
		return fmt.Errorf("pipelineId is required")
	}
	if p.StepIndex < 0 {
		return fmt.Errorf("stepIndex must be >= 0")
	}
	return nil
}
