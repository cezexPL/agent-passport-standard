package envelope

import (
	"testing"
)

func testConfig() Config {
	return Config{
		AgentDID:          "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		AgentSnapshotHash: "0x0000000000000000000000000000000000000000000000000000000000000aaa",
		Capabilities: Capabilities{
			Allowed: []string{"code_read", "code_write"},
			Denied:  []string{"network_egress"},
		},
		Sandbox: SandboxProfile{
			Runtime: "gvisor",
			Resources: Resources{
				CPUCores:       1,
				MemoryMB:       1024,
				DiskMB:         2048,
				TimeoutSeconds: 600,
				MaxPids:        64,
			},
			Network: NetworkPolicy{
				Policy:        "deny-all",
				AllowedEgress: []string{},
				DNSResolution: false,
			},
			Filesystem: Filesystem{
				WritablePaths: []string{"/workspace"},
				ReadonlyPaths: []string{"/usr"},
				DeniedPaths:   []string{"/etc/shadow"},
			},
		},
		Memory: MemoryBoundary{
			Isolation: "strict",
			Policy:    "private-by-design",
			Rules: MemoryRules{
				DNACopyable:        true,
				MemoryCopyable:     false,
				ContextShared:      false,
				LogsRetained:       true,
				LogsContentVisible: false,
			},
			Vault: Vault{
				Type:       "platform-managed",
				Encryption: "aes-256-gcm",
				KeyHolder:  "agent_owner",
			},
		},
		Trust: TrustInfo{
			Tier:               2,
			AttestationCount:   5,
			HighestAttestation: "ReliabilityGold",
			BenchmarkCoverage:  0.8,
			AnomalyScore:       0.02,
		},
	}
}

func TestNew(t *testing.T) {
	e, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != "SecurityEnvelope" {
		t.Errorf("type = %s, want SecurityEnvelope", e.Type)
	}
	if e.EnvelopeHash == "" {
		t.Error("envelope_hash should not be empty")
	}
}

func TestNew_MissingDID(t *testing.T) {
	cfg := testConfig()
	cfg.AgentDID = ""
	_, err := New(cfg)
	if err == nil {
		t.Error("should fail without agent_did")
	}
}

func TestHash_Deterministic(t *testing.T) {
	e, _ := New(testConfig())
	h1, _ := e.Hash()
	h2, _ := e.Hash()
	if h1 != h2 {
		t.Errorf("non-deterministic: %s != %s", h1, h2)
	}
}

func TestValidate_OK(t *testing.T) {
	e, _ := New(testConfig())
	if err := e.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_Tier1_NoAttestations(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.Tier = 1
	cfg.Trust.AttestationCount = 0
	e, _ := New(cfg)
	if err := e.Validate(); err == nil {
		t.Error("tier 1 with 0 attestations should fail")
	}
}

func TestValidate_Tier2_LowCoverage(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.Tier = 2
	cfg.Trust.BenchmarkCoverage = 0.5
	e, _ := New(cfg)
	if err := e.Validate(); err == nil {
		t.Error("tier 2 with 0.5 coverage should fail")
	}
}

func TestValidate_Tier3_Insufficient(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.Tier = 3
	cfg.Trust.AttestationCount = 5
	cfg.Trust.BenchmarkCoverage = 0.9
	e, _ := New(cfg)
	if err := e.Validate(); err == nil {
		t.Error("tier 3 with insufficient attestations should fail")
	}
}

func TestValidate_InvalidRuntime(t *testing.T) {
	cfg := testConfig()
	cfg.Sandbox.Runtime = "docker"
	e, _ := New(cfg)
	if err := e.Validate(); err == nil {
		t.Error("invalid runtime should fail")
	}
}

func TestFromJSON_Roundtrip(t *testing.T) {
	e, _ := New(testConfig())
	data, err := e.JSON()
	if err != nil {
		t.Fatal(err)
	}
	e2, err := FromJSON(data, false)
	if err != nil {
		t.Fatal(err)
	}
	if e2.AgentDID != e.AgentDID {
		t.Error("agent_did mismatch")
	}
}
