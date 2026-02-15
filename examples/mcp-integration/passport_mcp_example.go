package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/agent-passport/standard-go/crypto"
	"github.com/agent-passport/standard-go/passport"
)

// MCPToolAnnotation is a tiny metadata envelope that carries passport trust data.
type MCPToolAnnotation struct {
	ToolName          string            `json:"tool_name"`
	PassportDID       string            `json:"passport_did"`
	PassportHash      string            `json:"passport_hash"`
	Permissions       []string          `json:"permissions"`
	AgentCustomization map[string]string `json:"agent_customization"`
}

func buildAgentPassportHash(p *passport.AgentPassport) (string, error) {
	return p.Hash()
}

func buildToolAnnotation(p *passport.AgentPassport) (string, error) {
	passportHash, err := buildAgentPassportHash(p)
	if err != nil {
		return "", err
	}

	annotation := MCPToolAnnotation{
		ToolName:     "agent.passport.check",
		PassportDID:  p.ID,
		PassportHash: passportHash,
		Permissions:  []string{"agent.exchange", "agent.verify"},
		AgentCustomization: map[string]string{
			"sandbox":          "gvisor",
			"security_tier":    "2",
			"allowed_protocols": "mcp",
		},
	}
	payload, err := json.MarshalIndent(annotation, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func verifyAnnotationPayload(passportHash string, annotationJSON string) bool {
	var annotation MCPToolAnnotation
	if err := json.Unmarshal([]byte(annotationJSON), &annotation); err != nil {
		log.Printf("invalid annotation JSON: %v", err)
		return false
	}
	return annotation.PassportHash == passportHash
}

func main() {
	pass := &passport.AgentPassport{ID: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"}
	pass.Context = "https://agentpassport.org/v0.1"
	pass.SpecVersion = "0.1.0"
	pass.Type = "AgentPassport"
	pass.Snapshot.Hash = "0x7a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"

	annotation, err := buildToolAnnotation(pass)
	if err != nil {
		log.Fatal(err)
	}

	head := crypto.Keccak256([]byte("tool-card:" + annotation))
	valid := verifyAnnotationPayload(head, annotation)
	fmt.Println("annotation:", annotation)
	fmt.Println("hash-match:", valid)
	fmt.Println("advertised passport hash prefix:", head[:12])
}
