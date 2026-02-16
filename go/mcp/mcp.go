// Package mcp implements the MCP Security Profile types from APS v1.1 §17.
package mcp

import (
	"fmt"
	"time"
)

// MCPSecurityProfile defines the security profile for MCP tool usage.
type MCPSecurityProfile struct {
	ToolAllowlist      []ToolAllowEntry  `json:"toolAllowlist"`
	EgressPolicy       EgressPolicy      `json:"egressPolicy"`
	DataClassification string            `json:"dataClassification"`
	ServerAttestation  string            `json:"serverAttestation"`
	ValidationRules    []string          `json:"validationRules"`
	ExfiltrationGuards []string          `json:"exfiltrationGuards"`
	AuditConfig        AuditConfig       `json:"auditConfig"`
}

// ToolAllowEntry defines a single allowed tool.
type ToolAllowEntry struct {
	ServerHash            string `json:"serverHash"`
	ToolName              string `json:"toolName"`
	Version               string `json:"version"`
	DataClassificationMax string `json:"dataClassificationMax"`
}

// EgressPolicy defines network egress restrictions.
type EgressPolicy struct {
	DefaultDeny    bool     `json:"defaultDeny"`
	AllowedDomains []string `json:"allowedDomains"`
	AllowedIPs     []string `json:"allowedIPs"`
}

// AuditConfig defines audit logging configuration.
type AuditConfig struct {
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retentionDays"`
	Destination   string `json:"destination"`
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp         time.Time `json:"timestamp"`
	ToolName          string    `json:"toolName"`
	InputHash         string    `json:"inputHash"`
	OutputHash        string    `json:"outputHash"`
	Duration          string    `json:"duration"`
	AgentDID          string    `json:"agentDID"`
	PreviousEntryHash string    `json:"previousEntryHash"`
}

// Validate checks that the MCPSecurityProfile is well-formed.
func (p *MCPSecurityProfile) Validate() error {
	if len(p.ToolAllowlist) == 0 {
		return fmt.Errorf("toolAllowlist must not be empty")
	}
	for i, e := range p.ToolAllowlist {
		if e.ServerHash == "" {
			return fmt.Errorf("toolAllowlist[%d]: serverHash is required", i)
		}
		if e.ToolName == "" {
			return fmt.Errorf("toolAllowlist[%d]: toolName is required", i)
		}
	}
	if p.DataClassification == "" {
		return fmt.Errorf("dataClassification is required")
	}
	if p.ServerAttestation == "" {
		return fmt.Errorf("serverAttestation is required")
	}
	return nil
}
