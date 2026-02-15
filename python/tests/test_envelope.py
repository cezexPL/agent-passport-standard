"""Tests for SecurityEnvelope."""
import pytest
from aps.envelope import SecurityEnvelope, EnvelopeConfig
from aps.crypto import generate_key_pair


def _sandbox(runtime="gvisor", policy="deny-all"):
    return {
        "runtime": runtime,
        "resources": {"cpu_cores": 1, "memory_mb": 1024, "disk_mb": 2048,
                      "timeout_seconds": 600, "max_pids": 64},
        "network": {"policy": policy, "allowed_egress": [], "dns_resolution": False},
        "filesystem": {"writable_paths": ["/workspace"], "readonly_paths": ["/usr"],
                       "denied_paths": ["/etc/shadow"]},
    }


def _memory():
    return {
        "isolation": "strict", "policy": "private-by-design",
        "rules": {"dna_copyable": True, "memory_copyable": False,
                  "context_shared": False, "logs_retained": True,
                  "logs_content_visible": False},
        "vault": {"type": "platform-managed", "encryption": "aes-256-gcm",
                  "key_holder": "agent_owner"},
    }


def _cfg(tier=0, att=0, cov=0.0, runtime="gvisor", policy="deny-all"):
    return EnvelopeConfig(
        agent_did="did:key:z6MkAgent",
        agent_snapshot_hash="0x" + "aa" * 32,
        capabilities={"allowed": ["code_read"], "denied": []},
        sandbox=_sandbox(runtime, policy),
        memory=_memory(),
        trust={"tier": tier, "attestation_count": att,
               "highest_attestation": "", "benchmark_coverage": cov,
               "anomaly_score": 0.0},
    )


def test_create_validate_tiers():
    # Tier 0 — always ok
    e = SecurityEnvelope.new(_cfg(0))
    e.validate()

    # Tier 1
    e1 = SecurityEnvelope.new(_cfg(1, att=1))
    e1.validate()
    e1_bad = SecurityEnvelope.new(_cfg(1, att=0))
    with pytest.raises(ValueError):
        e1_bad.validate()

    # Tier 2
    e2 = SecurityEnvelope.new(_cfg(2, att=3, cov=0.8))
    e2.validate()
    with pytest.raises(ValueError):
        SecurityEnvelope.new(_cfg(2, att=2, cov=0.8)).validate()
    with pytest.raises(ValueError):
        SecurityEnvelope.new(_cfg(2, att=3, cov=0.5)).validate()

    # Tier 3
    e3 = SecurityEnvelope.new(_cfg(3, att=10, cov=0.95))
    e3.validate()


def test_reject_invalid_runtime():
    e = SecurityEnvelope.new(_cfg())
    e.sandbox["runtime"] = "docker"
    with pytest.raises(ValueError, match="invalid runtime"):
        e.validate()


def test_reject_invalid_network_policy():
    e = SecurityEnvelope.new(_cfg())
    e.sandbox["network"]["policy"] = "yolo"
    with pytest.raises(ValueError, match="invalid network policy"):
        e.validate()


def test_sign_verify():
    pub, priv = generate_key_pair()
    e = SecurityEnvelope.new(_cfg())
    e.sign(priv)
    assert e.proof is not None
    assert e.verify(pub)


def test_from_json_roundtrip():
    e = SecurityEnvelope.new(_cfg())
    data = e.to_json()
    e2 = SecurityEnvelope.from_json(data)
    assert e2.agent_did == e.agent_did
    assert e2.envelope_hash == e.envelope_hash
