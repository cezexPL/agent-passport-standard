package main

import (
	"encoding/json"
	"fmt"

	"github.com/agent-passport/standard-go/crypto"
)

func main() {
	// 1. keccak256-empty-object
	canonical1, _ := crypto.CanonicalizeJSON(map[string]interface{}{})
	fmt.Println("empty-object canonical:", string(canonical1))
	fmt.Println("empty-object hash:", crypto.Keccak256(canonical1))

	// 2. keccak256-simple-passport
	input2 := map[string]interface{}{
		"id":   "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"type": "AgentPassport",
	}
	canonical2, _ := crypto.CanonicalizeJSON(input2)
	fmt.Println("\nsimple-passport canonical:", string(canonical2))
	fmt.Println("simple-passport hash:", crypto.Keccak256(canonical2))

	// 3. merkle-tree-4-leaves
	leaves := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
		"0x0000000000000000000000000000000000000000000000000000000000000003",
		"0x0000000000000000000000000000000000000000000000000000000000000004",
	}
	mt := crypto.NewMerkleTree(leaves)
	fmt.Println("\nmerkle root:", mt.Root())
	proof := mt.Proof(0)
	fmt.Println("merkle proof for index 0:", proof)

	// 4. passport-hash-with-benchmarks
	input4 := map[string]interface{}{
		"skills": map[string]interface{}{
			"entries": []interface{}{
				map[string]interface{}{
					"name": "go-developer", "version": "1.0.0", "description": "Go backend",
					"capabilities": []interface{}{"code_write"},
					"hash": "0x0000000000000000000000000000000000000000000000000000000000000abc",
				},
			},
			"frozen": false,
		},
		"soul": map[string]interface{}{
			"personality": "focused",
			"work_style":  "test-first",
			"constraints": []interface{}{},
			"hash":        "0x0000000000000000000000000000000000000000000000000000000000000def",
			"frozen":      false,
		},
		"policies": map[string]interface{}{
			"policy_set_hash": "0x0000000000000000000000000000000000000000000000000000000000000123",
			"summary":         []interface{}{"can_bid"},
		},
	}
	canonical4, _ := crypto.CanonicalizeJSON(input4)
	fmt.Println("\npassport-hash canonical:", string(canonical4))
	fmt.Println("passport-hash:", crypto.Keccak256(canonical4))

	// 5. work-receipt-hash
	input5 := map[string]interface{}{
		"receipt_id": "550e8400-e29b-41d4-a716-446655440000",
		"job_id":     "550e8400-e29b-41d4-a716-446655440001",
		"agent_did":  "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"client_did": "did:key:z6MkpOwnerABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
		"agent_snapshot": map[string]interface{}{
			"version": 1,
			"hash":    "0x0000000000000000000000000000000000000000000000000000000000000aaa",
		},
		"events": []interface{}{
			map[string]interface{}{"type": "claim", "timestamp": "2026-02-14T01:00:00Z", "payload_hash": "0x0000000000000000000000000000000000000000000000000000000000000001", "signature": "z_claim_sig"},
			map[string]interface{}{"type": "submit", "timestamp": "2026-02-14T01:30:00Z", "payload_hash": "0x0000000000000000000000000000000000000000000000000000000000000002", "signature": "z_submit_sig"},
			map[string]interface{}{"type": "verify", "timestamp": "2026-02-14T01:35:00Z", "payload_hash": "0x0000000000000000000000000000000000000000000000000000000000000003", "signature": "z_verify_sig", "result": map[string]interface{}{"status": "accepted", "score": 87}},
			map[string]interface{}{"type": "payout", "timestamp": "2026-02-14T01:40:00Z", "payload_hash": "0x0000000000000000000000000000000000000000000000000000000000000004", "signature": "z_payout_sig", "amount": map[string]interface{}{"value": 500, "unit": "points"}},
		},
	}
	canonical5, _ := crypto.CanonicalizeJSON(input5)
	fmt.Println("\nreceipt canonical:", string(canonical5))
	fmt.Println("receipt hash:", crypto.Keccak256(canonical5))

	// 6. security-envelope-hash
	input6 := map[string]interface{}{
		"agent_did":           "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		"agent_snapshot_hash": "0x0000000000000000000000000000000000000000000000000000000000000aaa",
		"capabilities": map[string]interface{}{
			"allowed": []interface{}{"code_read", "code_write"},
			"denied":  []interface{}{"network_egress"},
		},
		"sandbox": map[string]interface{}{
			"runtime": "gvisor",
			"resources": map[string]interface{}{
				"cpu_cores": 1, "memory_mb": 1024, "disk_mb": 2048, "timeout_seconds": 600, "max_pids": 64,
			},
			"network": map[string]interface{}{
				"policy": "deny-all", "allowed_egress": []interface{}{}, "dns_resolution": false,
			},
			"filesystem": map[string]interface{}{
				"writable_paths": []interface{}{"/workspace"},
				"readonly_paths": []interface{}{"/usr"},
				"denied_paths":   []interface{}{"/etc/shadow"},
			},
		},
		"memory": map[string]interface{}{
			"isolation": "strict",
			"policy":    "private-by-design",
			"rules": map[string]interface{}{
				"dna_copyable": true, "memory_copyable": false, "context_shared": false, "logs_retained": true, "logs_content_visible": false,
			},
			"vault": map[string]interface{}{
				"type": "platform-managed", "encryption": "aes-256-gcm", "key_holder": "agent_owner",
			},
		},
		"trust": map[string]interface{}{
			"tier": 2, "attestation_count": 5, "highest_attestation": "ReliabilityGold", "benchmark_coverage": 0.8, "anomaly_score": 0.02,
		},
	}
	canonical6, _ := crypto.CanonicalizeJSON(input6)
	fmt.Println("\nenvelope canonical:", string(canonical6))
	fmt.Println("envelope hash:", crypto.Keccak256(canonical6))

	// Also dump JSON for verification
	_ = json.Compact
}
