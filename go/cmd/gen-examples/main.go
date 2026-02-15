package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/cezexPL/agent-passport-standard/go/crypto"
	"github.com/cezexPL/agent-passport-standard/go/envelope"
	"github.com/cezexPL/agent-passport-standard/go/passport"
	"github.com/cezexPL/agent-passport-standard/go/receipt"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func encodeBase58(data []byte) string {
	n := new(big.Int).SetBytes(data)
	mod := new(big.Int)
	zero := big.NewInt(0)
	base := big.NewInt(58)
	var result []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append([]byte{base58Alphabet[mod.Int64()]}, result...)
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		result = append([]byte{base58Alphabet[0]}, result...)
	}
	return string(result)
}

func pubKeyToDIDKey(pub []byte) string {
	// did:key uses multicodec ed25519-pub (0xed01) prefix + multibase-base58btc (z)
	multicodec := append([]byte{0xed, 0x01}, pub...)
	return "did:key:z" + encodeBase58(multicodec)
}

func main() {
	pub, priv, _ := crypto.GenerateKeyPair()
	pubHex := hex.EncodeToString(pub)
	did := pubKeyToDIDKey(pub)

	ownerPub, _, _ := crypto.GenerateKeyPair()
	ownerDID := pubKeyToDIDKey(ownerPub)

	clientPub, _, _ := crypto.GenerateKeyPair()
	clientDID := pubKeyToDIDKey(clientPub)

	// 1. Generate valid passport
	p, err := passport.New(passport.Config{
		ID:        did,
		PublicKey: pubHex,
		OwnerDID:  ownerDID,
		Skills: []passport.Skill{
			{
				Name:         "go-backend",
				Version:      "1.0.0",
				Description:  "Production-grade Go backend development",
				Capabilities: []string{"code_write", "code_review", "test_run"},
				Hash:         crypto.Keccak256([]byte("go-backend-skill-v1")),
			},
			{
				Name:         "security-audit",
				Version:      "1.0.0",
				Description:  "Security vulnerability assessment and code hardening",
				Capabilities: []string{"code_review", "security_scan"},
				Hash:         crypto.Keccak256([]byte("security-audit-skill-v1")),
			},
		},
		Soul: passport.Soul{
			Personality: "Methodical, security-focused, test-driven developer",
			WorkStyle:   "Test-first development with comprehensive error handling",
			Constraints: []string{
				"Never execute arbitrary code without sandbox",
				"Always validate inputs before processing",
			},
			Hash:   crypto.Keccak256([]byte("soul-v1")),
			Frozen: false,
		},
		Policies: passport.Policies{
			PolicySetHash: crypto.Keccak256([]byte("policy-set-v1")),
			Summary: []string{
				"Only execute code in sandboxed environments",
				"Respect rate limits and resource constraints",
			},
		},
		Lineage: passport.Lineage{
			Kind:       "single",
			Parents:    []string{},
			Generation: 0,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "passport: %v\n", err)
		os.Exit(1)
	}
	if err := p.Sign(priv); err != nil {
		fmt.Fprintf(os.Stderr, "sign passport: %v\n", err)
		os.Exit(1)
	}

	// Self-verify
	ok, err := p.Verify(pub)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "❌ self-verify passport FAILED: ok=%v err=%v\n", ok, err)
		os.Exit(1)
	}
	writeJSON("../examples/example-passport.json", p)
	fmt.Println("✅ example-passport.json — signed & verified")

	// 2. Generate valid work receipt
	r, _ := receipt.New(receipt.Config{
		ReceiptID: "550e8400-e29b-41d4-a716-446655440000",
		JobID:     "550e8400-e29b-41d4-a716-446655440001",
		AgentDID:  did,
		ClientDID: clientDID,
		AgentSnapshot: receipt.AgentSnapshot{
			Version: 1,
			Hash:    p.Snapshot.Hash,
		},
	})
	now := time.Now().UTC()
	r.AddEvent(receipt.ReceiptEvent{
		Type:        "claim",
		Timestamp:   now.Add(-30 * time.Minute).Format(time.RFC3339),
		PayloadHash: crypto.Keccak256([]byte("claim-payload")),
		Signature:   hex.EncodeToString([]byte("claim-sig-placeholder")),
	})
	r.AddEvent(receipt.ReceiptEvent{
		Type:        "submit",
		Timestamp:   now.Add(-10 * time.Minute).Format(time.RFC3339),
		PayloadHash: crypto.Keccak256([]byte("submit-payload")),
		Signature:   hex.EncodeToString([]byte("submit-sig-placeholder")),
	})
	r.AddEvent(receipt.ReceiptEvent{
		Type:        "verify",
		Timestamp:   now.Add(-5 * time.Minute).Format(time.RFC3339),
		PayloadHash: crypto.Keccak256([]byte("verify-payload")),
		Signature:   hex.EncodeToString([]byte("verify-sig-placeholder")),
		Result:      &receipt.VerifyResult{Status: "accepted", Score: 92},
	})
	r.AddEvent(receipt.ReceiptEvent{
		Type:        "payout",
		Timestamp:   now.Format(time.RFC3339),
		PayloadHash: crypto.Keccak256([]byte("payout-payload")),
		Signature:   hex.EncodeToString([]byte("payout-sig-placeholder")),
		Amount:      &receipt.PayoutAmount{Value: 750, Unit: "points"},
	})
	r.Sign(priv)
	writeJSON("../examples/example-receipt.json", r)
	fmt.Println("✅ example-receipt.json — signed")

	// 3. Generate valid security envelope
	e, _ := envelope.New(envelope.Config{
		AgentDID:          did,
		AgentSnapshotHash: p.Snapshot.Hash,
		Capabilities: envelope.Capabilities{
			Allowed: []string{"code_read", "code_write", "test_run", "build"},
			Denied:  []string{"network_egress", "filesystem_root", "process_spawn"},
		},
		Sandbox: envelope.SandboxProfile{
			Runtime: "gvisor",
			Resources: envelope.Resources{
				CPUCores:       1,
				MemoryMB:       1024,
				DiskMB:         2048,
				TimeoutSeconds: 600,
				MaxPids:        64,
			},
			Network: envelope.NetworkPolicy{
				Policy:        "deny-all",
				AllowedEgress: []string{},
				DNSResolution: false,
			},
			Filesystem: envelope.Filesystem{
				WritablePaths: []string{"/workspace", "/tmp"},
				ReadonlyPaths: []string{"/usr", "/lib"},
				DeniedPaths:   []string{"/etc/shadow", "/root", "/proc"},
			},
		},
		Memory: envelope.MemoryBoundary{
			Isolation: "strict",
			Policy:    "private-by-design",
			Rules: envelope.MemoryRules{
				DNACopyable:        true,
				MemoryCopyable:     false,
				ContextShared:      false,
				LogsRetained:       true,
				LogsContentVisible: false,
			},
			Vault: envelope.Vault{
				Type:       "platform-managed",
				Encryption: "aes-256-gcm",
				KeyHolder:  "agent_owner",
			},
		},
		Trust: envelope.TrustInfo{
			Tier:               2,
			AttestationCount:   5,
			HighestAttestation: "ReliabilityGold",
			BenchmarkCoverage:  0.85,
			AnomalyScore:       0.02,
		},
	})
	e.Sign(priv)
	writeJSON("../examples/example-envelope.json", e)
	fmt.Println("✅ example-envelope.json — signed")

	// 4. Generate valid DNA
	dna := map[string]interface{}{
		"@context":  "https://agentpassport.org/v0.2/dna",
		"type":      "AgentDNA",
		"agent_id":  did,
		"version":   1,
		"skills":    p.Snapshot.Skills,
		"soul":      p.Snapshot.Soul,
		"policies":  p.Snapshot.Policies,
		"dna_hash":  p.Snapshot.Hash,
		"frozen":    false,
	}
	writeJSON("../examples/example-dna.json", dna)
	fmt.Println("✅ example-dna.json")

	// 5. Generate recovery request
	recovery := map[string]interface{}{
		"@context":    "https://agentpassport.org/v0.2/recovery",
		"type":        "RecoveryRequest",
		"agent_id":    did,
		"vault_hash":  crypto.Keccak256([]byte("vault-contents")),
		"key_hash":    crypto.Keccak256([]byte("encryption-key")),
		"encrypted_at": now.Format(time.RFC3339),
		"items":       []string{"skills", "soul", "memories"},
	}
	writeJSON("../examples/example-recovery.json", recovery)
	fmt.Println("✅ example-recovery.json")

	fmt.Printf("\nAgent DID:  %s\n", did)
	fmt.Printf("Owner DID:  %s\n", ownerDID)
	fmt.Printf("Public key: %s\n", pubHex)
}

func writeJSON(path string, v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, data, 0644)
}
