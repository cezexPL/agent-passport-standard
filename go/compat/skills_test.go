package compat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agent-passport/standard-go/passport"
)

func TestImportAgentSkill(t *testing.T) {
	// Create temp skill folder
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "go-developer")
	os.MkdirAll(filepath.Join(skillDir, "scripts"), 0755)

	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`# Go Developer

Expert Go backend development skill.

## Capabilities
- Code writing and review
- Testing and debugging
- Build and deploy
`), 0644)

	os.WriteFile(filepath.Join(skillDir, "scripts", "lint.sh"), []byte("#!/bin/bash\ngo vet ./..."), 0755)

	skill, err := ImportAgentSkill(skillDir)
	if err != nil {
		t.Fatalf("ImportAgentSkill: %v", err)
	}

	if skill.Name != "go-developer" {
		t.Errorf("name = %q, want go-developer", skill.Name)
	}
	if skill.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", skill.Version)
	}
	if len(skill.Capabilities) == 0 {
		t.Error("expected capabilities, got none")
	}
}

func TestExportAgentSkill(t *testing.T) {
	dir := t.TempDir()
	skill := &passport.Skill{
		Name:         "python-data",
		Version:      "2.0.0",
		Description:  "Python data pipeline development",
		Capabilities: []string{"code_write", "data_read"},
		Source:        "https://github.com/example/python-data",
	}

	err := ExportAgentSkill(skill, dir)
	if err != nil {
		t.Fatalf("ExportAgentSkill: %v", err)
	}

	// Check SKILL.md exists
	skillMD := filepath.Join(dir, "python-data", "SKILL.md")
	if _, err := os.Stat(skillMD); os.IsNotExist(err) {
		t.Error("SKILL.md not created")
	}

	// Check metadata.json exists
	metaJSON := filepath.Join(dir, "python-data", "metadata.json")
	if _, err := os.Stat(metaJSON); os.IsNotExist(err) {
		t.Error("metadata.json not created")
	}
}

func TestExportImportRoundtrip(t *testing.T) {
	dir := t.TempDir()
	original := &passport.Skill{
		Name:         "api-builder",
		Version:      "1.0.0",
		Description:  "REST API builder with testing",
		Capabilities: []string{"code_write", "test_run", "build"},
		Source:        "https://example.com",
	}

	err := ExportAgentSkill(original, dir)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	imported, err := ImportAgentSkill(filepath.Join(dir, "api-builder"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if imported.Name != original.Name {
		t.Errorf("name mismatch: %q vs %q", imported.Name, original.Name)
	}
}

func TestLoadAgentsMD(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(`# Agents

## Instructions
- Always write tests first
- Use Go standard library when possible
- Follow project conventions

## Constraints
- No external network access
- Max 1000 lines per file

## Tools
- go build
- go test
- golangci-lint
`), 0644)

	result, err := LoadAgentsMD(dir)
	if err != nil {
		t.Fatalf("LoadAgentsMD: %v", err)
	}

	if len(result.Instructions) != 3 {
		t.Errorf("instructions count = %d, want 3", len(result.Instructions))
	}
	if len(result.Constraints) != 2 {
		t.Errorf("constraints count = %d, want 2", len(result.Constraints))
	}
	if len(result.Tools) != 3 {
		t.Errorf("tools count = %d, want 3", len(result.Tools))
	}
}

func TestLoadAgentsMD_NotFound(t *testing.T) {
	_, err := LoadAgentsMD("/nonexistent")
	if err == nil {
		t.Error("expected error for missing AGENTS.md")
	}
}
