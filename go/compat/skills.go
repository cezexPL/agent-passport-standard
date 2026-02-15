// Package compat provides compatibility bridges between Agent Passport Standard
// and existing agent ecosystem standards (Agent Skills, AGENTS.md, MCP).
package compat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agent-passport/standard-go/passport"
)

// AgentSkillFolder represents an Agent Skills folder structure.
// See: https://github.com/anthropics/agent-skills
type AgentSkillFolder struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Scripts     []string `json:"scripts,omitempty"`
	References  []string `json:"references,omitempty"`
	SkillMD     string   `json:"skill_md"` // content of SKILL.md
}

// ImportAgentSkill reads an Agent Skills folder and converts it to a passport.Skill.
func ImportAgentSkill(skillDir string) (*passport.Skill, error) {
	skillMDPath := filepath.Join(skillDir, "SKILL.md")
	content, err := os.ReadFile(skillMDPath)
	if err != nil {
		return nil, fmt.Errorf("read SKILL.md: %w", err)
	}

	name := filepath.Base(skillDir)
	description := extractFirstLine(string(content))

	// Scan for scripts
	var scripts []string
	scriptsDir := filepath.Join(skillDir, "scripts")
	if entries, err := os.ReadDir(scriptsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				scripts = append(scripts, e.Name())
			}
		}
	}

	// Derive capabilities from content heuristics
	capabilities := inferCapabilities(string(content))

	return &passport.Skill{
		Name:         name,
		Version:      "1.0.0",
		Description:  description,
		Capabilities: capabilities,
		Source:        "agent-skills://" + name,
	}, nil
}

// ExportAgentSkill writes a passport.Skill as an Agent Skills folder.
func ExportAgentSkill(skill *passport.Skill, outputDir string) error {
	skillDir := filepath.Join(outputDir, skill.Name)
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Write SKILL.md
	md := fmt.Sprintf("# %s\n\n%s\n\nVersion: %s\n\n## Capabilities\n\n",
		skill.Name, skill.Description, skill.Version)
	for _, cap := range skill.Capabilities {
		md += fmt.Sprintf("- %s\n", cap)
	}

	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(md), 0644); err != nil {
		return fmt.Errorf("write SKILL.md: %w", err)
	}

	// Write metadata.json
	meta, _ := json.MarshalIndent(skill, "", "  ")
	if err := os.WriteFile(filepath.Join(skillDir, "metadata.json"), meta, 0644); err != nil {
		return fmt.Errorf("write metadata.json: %w", err)
	}

	return nil
}

// AgentsMD represents parsed AGENTS.md instructions.
type AgentsMD struct {
	Raw          string   `json:"raw"`
	Instructions []string `json:"instructions"`
	Constraints  []string `json:"constraints"`
	Tools        []string `json:"tools"`
}

// LoadAgentsMD reads and parses an AGENTS.md file from a repository.
func LoadAgentsMD(repoPath string) (*AgentsMD, error) {
	agentsPath := filepath.Join(repoPath, "AGENTS.md")
	content, err := os.ReadFile(agentsPath)
	if err != nil {
		return nil, fmt.Errorf("read AGENTS.md: %w", err)
	}

	result := &AgentsMD{Raw: string(content)}

	lines := strings.Split(string(content), "\n")
	section := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(trimmed, "#") {
			if strings.Contains(lower, "instruction") || strings.Contains(lower, "rules") {
				section = "instructions"
			} else if strings.Contains(lower, "constraint") || strings.Contains(lower, "restriction") {
				section = "constraints"
			} else if strings.Contains(lower, "tool") || strings.Contains(lower, "mcp") {
				section = "tools"
			} else {
				section = ""
			}
			continue
		}

		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			item := strings.TrimLeft(trimmed, "-* ")
			switch section {
			case "instructions":
				result.Instructions = append(result.Instructions, item)
			case "constraints":
				result.Constraints = append(result.Constraints, item)
			case "tools":
				result.Tools = append(result.Tools, item)
			}
		}
	}

	return result, nil
}

func extractFirstLine(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return trimmed
		}
	}
	return ""
}

func inferCapabilities(content string) []string {
	lower := strings.ToLower(content)
	var caps []string

	if strings.Contains(lower, "code") || strings.Contains(lower, "develop") {
		caps = append(caps, "code_write")
	}
	if strings.Contains(lower, "test") {
		caps = append(caps, "test_run")
	}
	if strings.Contains(lower, "debug") {
		caps = append(caps, "debug")
	}
	if strings.Contains(lower, "build") {
		caps = append(caps, "build")
	}
	if strings.Contains(lower, "review") || strings.Contains(lower, "audit") {
		caps = append(caps, "code_review")
	}
	if strings.Contains(lower, "data") || strings.Contains(lower, "analyz") {
		caps = append(caps, "data_read")
	}

	if len(caps) == 0 {
		caps = append(caps, "general")
	}
	return caps
}
