package mcp

import (
	"encoding/json"
	"testing"
	"time"
)

func sampleProfile() MCPSecurityProfile {
	return MCPSecurityProfile{
		ToolAllowlist: []ToolAllowEntry{
			{ServerHash: "sha256:abc123", ToolName: "web_search", Version: "1.0", DataClassificationMax: "public"},
		},
		EgressPolicy: EgressPolicy{
			DefaultDeny:    true,
			AllowedDomains: []string{"api.example.com"},
			AllowedIPs:     []string{"10.0.0.1/32"},
		},
		DataClassification: "confidential",
		ServerAttestation:  "sha256:server123",
		ValidationRules:    []string{"no-pii-leak"},
		ExfiltrationGuards: []string{"output-filter"},
		AuditConfig: AuditConfig{
			Enabled:       true,
			RetentionDays: 90,
			Destination:   "s3://audit-logs",
		},
	}
}

func TestMCPSecurityProfileRoundTrip(t *testing.T) {
	p := sampleProfile()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p2 MCPSecurityProfile
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p2.DataClassification != p.DataClassification {
		t.Errorf("got %q, want %q", p2.DataClassification, p.DataClassification)
	}
	if len(p2.ToolAllowlist) != 1 || p2.ToolAllowlist[0].ToolName != "web_search" {
		t.Error("toolAllowlist mismatch")
	}
}

func TestMCPSecurityProfileValidate(t *testing.T) {
	p := sampleProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// empty allowlist
	bad := sampleProfile()
	bad.ToolAllowlist = nil
	if err := bad.Validate(); err == nil {
		t.Error("expected error for empty allowlist")
	}

	// missing dataClassification
	bad2 := sampleProfile()
	bad2.DataClassification = ""
	if err := bad2.Validate(); err == nil {
		t.Error("expected error for missing dataClassification")
	}
}

func TestAuditEntryRoundTrip(t *testing.T) {
	e := AuditEntry{
		Timestamp:         time.Now().UTC().Truncate(time.Millisecond),
		ToolName:          "web_search",
		InputHash:         "sha256:in",
		OutputHash:        "sha256:out",
		Duration:          "150ms",
		AgentDID:          "did:key:z123",
		PreviousEntryHash: "sha256:prev",
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var e2 AuditEntry
	if err := json.Unmarshal(data, &e2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e2.ToolName != e.ToolName {
		t.Errorf("toolName mismatch")
	}
}
