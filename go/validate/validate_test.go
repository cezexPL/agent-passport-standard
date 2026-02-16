package validate

import (
	"encoding/json"
	"testing"
)

func validPassportMap() map[string]interface{} {
	return map[string]interface{}{
		"@context":     "https://agentpassport.org/v0.1",
		"spec_version": "0.1.0",
		"type":         "AgentPassport",
		"id":           "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"keys": map[string]interface{}{
			"signing": map[string]interface{}{
				"algorithm":  "Ed25519",
				"public_key": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
			},
		},
		"genesis_owner": map[string]interface{}{
			"id":        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
			"bound_at":  "2025-01-01T00:00:00Z",
			"immutable": true,
		},
		"current_owner": map[string]interface{}{
			"id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		},
		"snapshot": map[string]interface{}{
			"version":    1,
			"hash":       "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"prev_hash":  nil,
			"created_at": "2025-01-01T00:00:00Z",
			"skills": map[string]interface{}{
				"entries": []interface{}{
					map[string]interface{}{
						"name":         "go-dev",
						"version":      "1.0.0",
						"description":  "Go development",
						"capabilities": []interface{}{"code_write"},
						"hash":         "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
					},
				},
				"frozen": false,
			},
			"soul": map[string]interface{}{
				"personality":  "focused",
				"work_style":   "test-first",
				"constraints":  []interface{}{},
				"hash":         "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"frozen":       false,
			},
			"policies": map[string]interface{}{
				"policy_set_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"summary":         []interface{}{"can_bid"},
			},
		},
		"lineage": map[string]interface{}{
			"kind":       "single",
			"parents":    []interface{}{},
			"generation": 0,
		},
		"proof": map[string]interface{}{
			"type":                "Ed25519Signature2020",
			"created":             "2025-01-01T00:00:00Z",
			"verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#keys-1",
			"proofPurpose":       "assertionMethod",
			"proofValue":         "zSIG",
		},
	}
}

func toJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestValidPassport(t *testing.T) {
	if err := ValidatePassport(toJSON(validPassportMap())); err != nil {
		t.Fatalf("valid passport failed: %v", err)
	}
}

func TestMissingContext(t *testing.T) {
	m := validPassportMap()
	delete(m, "@context")
	if err := ValidatePassport(toJSON(m)); err == nil {
		t.Fatal("expected error for missing @context")
	}
}

func TestMissingID(t *testing.T) {
	m := validPassportMap()
	delete(m, "id")
	if err := ValidatePassport(toJSON(m)); err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestWrongTypeSpecVersion(t *testing.T) {
	m := validPassportMap()
	m["spec_version"] = 123
	if err := ValidatePassport(toJSON(m)); err == nil {
		t.Fatal("expected error for numeric spec_version")
	}
}

func TestExtraFields(t *testing.T) {
	// passport schema has additionalProperties: false, so extra fields should fail
	m := validPassportMap()
	m["extra_field"] = "hello"
	err := ValidatePassport(toJSON(m))
	if err == nil {
		t.Fatal("expected error for extra fields (additionalProperties: false)")
	}
}

func TestValidDNA(t *testing.T) {
	dna := map[string]interface{}{
		"@context": "https://agentpassport.org/v0.2/dna",
		"type":     "AgentDNA",
		"agent_id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"version":  1,
		"skills":   []interface{}{},
		"soul": map[string]interface{}{
			"personality": "focused",
			"work_style":  "test-first",
			"constraints": []interface{}{},
		},
		"policies": map[string]interface{}{
			"policy_set_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"summary":         []interface{}{"can_bid"},
		},
		"dna_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"frozen":   false,
	}
	if err := ValidateDNA(toJSON(dna)); err != nil {
		t.Fatalf("valid DNA failed: %v", err)
	}
}

func TestDNAMissingHash(t *testing.T) {
	dna := map[string]interface{}{
		"@context": "https://agentpassport.org/v0.2/dna",
		"type":     "AgentDNA",
		"agent_id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"version":  1,
		"skills":   []interface{}{},
		"soul": map[string]interface{}{
			"personality": "focused",
			"work_style":  "test-first",
			"constraints": []interface{}{},
		},
		"policies": map[string]interface{}{
			"policy_set_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"summary":         []interface{}{"can_bid"},
		},
		"frozen": false,
	}
	if err := ValidateDNA(toJSON(dna)); err == nil {
		t.Fatal("expected error for missing dna_hash")
	}
}

func TestSkillsEntriesWrongType(t *testing.T) {
	m := validPassportMap()
	snap := m["snapshot"].(map[string]interface{})
	snap["skills"] = map[string]interface{}{
		"entries": "not-an-array",
		"frozen":  false,
	}
	if err := ValidatePassport(toJSON(m)); err == nil {
		t.Fatal("expected error for skills.entries wrong type")
	}
}
