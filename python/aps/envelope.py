"""Security Envelope artifact."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import crypto


@dataclass
class EnvelopeConfig:
    agent_did: str
    agent_snapshot_hash: str
    capabilities: dict[str, Any]
    sandbox: dict[str, Any]
    memory: dict[str, Any]
    trust: dict[str, Any]


class SecurityEnvelope:
    def __init__(self) -> None:
        self.context: str = ""
        self.spec_version: str = ""
        self.type: str = ""
        self.agent_did: str = ""
        self.agent_snapshot_hash: str = ""
        self.capabilities: dict[str, Any] = {}
        self.sandbox: dict[str, Any] = {}
        self.memory: dict[str, Any] = {}
        self.trust: dict[str, Any] = {}
        self.envelope_hash: str = ""
        self.proof: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "@context": self.context,
            "spec_version": self.spec_version,
            "type": self.type,
            "agent_did": self.agent_did,
            "agent_snapshot_hash": self.agent_snapshot_hash,
            "capabilities": self.capabilities,
            "sandbox": self.sandbox,
            "memory": self.memory,
            "trust": self.trust,
            "envelope_hash": self.envelope_hash,
        }
        if self.proof is not None:
            d["proof"] = self.proof
        return d

    @staticmethod
    def new(cfg: EnvelopeConfig) -> "SecurityEnvelope":
        if not cfg.agent_did:
            raise ValueError("agent_did is required")

        e = SecurityEnvelope()
        e.context = "https://agentpassport.org/v0.1"
        e.spec_version = "0.1.0"
        e.type = "SecurityEnvelope"
        e.agent_did = cfg.agent_did
        e.agent_snapshot_hash = cfg.agent_snapshot_hash
        e.capabilities = cfg.capabilities
        e.sandbox = cfg.sandbox
        e.memory = cfg.memory
        e.trust = cfg.trust
        e.envelope_hash = e.hash()
        return e

    def hash(self) -> str:
        return crypto.hash_excluding_fields(self.to_dict(), "proof")

    def validate(self) -> None:
        if not self.agent_did:
            raise ValueError("agent_did is required")

        tier = self.trust.get("tier", 0)
        if tier < 0 or tier > 3:
            raise ValueError(f"trust tier must be 0-3, got {tier}")

        att = self.trust.get("attestation_count", 0)
        cov = self.trust.get("benchmark_coverage", 0.0)

        if tier == 1 and att < 1:
            raise ValueError(f"tier 1 requires >= 1 attestation, got {att}")
        if tier == 2:
            if att < 3:
                raise ValueError(f"tier 2 requires >= 3 attestations, got {att}")
            if cov < 0.8:
                raise ValueError(f"tier 2 requires >= 0.8 benchmark coverage, got {cov}")
        if tier == 3:
            if att < 10:
                raise ValueError(f"tier 3 requires >= 10 attestations, got {att}")
            if cov < 0.95:
                raise ValueError(f"tier 3 requires >= 0.95 benchmark coverage, got {cov}")

        valid_runtimes = {"gvisor", "firecracker", "wasm", "none"}
        rt = self.sandbox.get("runtime", "")
        if rt not in valid_runtimes:
            raise ValueError(f"invalid runtime: {rt}")

        valid_policies = {"deny-all", "allow-list", "unrestricted"}
        net = self.sandbox.get("network", {})
        pol = net.get("policy", "") if isinstance(net, dict) else ""
        if pol not in valid_policies:
            raise ValueError(f"invalid network policy: {pol}")

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        self.envelope_hash = self.hash()
        saved = self.proof
        self.proof = None
        try:
            canonical = crypto.canonicalize_json(self.to_dict())
        except Exception:
            self.proof = saved
            raise
        sig = crypto.ed25519_sign(private_key, canonical)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.proof = {
            "type": "Ed25519Signature2020",
            "created": now,
            "verification_method": self.agent_did + "#key-1",
            "proof_purpose": "assertionMethod",
            "proof_value": sig,
        }

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        if self.proof is None:
            raise ValueError("no proof present")
        proof = self.proof
        self.proof = None
        try:
            canonical = crypto.canonicalize_json(self.to_dict())
            return crypto.ed25519_verify(public_key, canonical, proof["proof_value"])
        finally:
            self.proof = proof

    def to_json(self) -> bytes:
        return crypto.canonicalize_json(self.to_dict())

    @staticmethod
    def from_json(data: bytes | str) -> "SecurityEnvelope":
        raw = json.loads(data)
        e = SecurityEnvelope()
        e.context = raw.get("@context", "")
        e.spec_version = raw.get("spec_version", "")
        e.type = raw.get("type", "")
        e.agent_did = raw.get("agent_did", "")
        e.agent_snapshot_hash = raw.get("agent_snapshot_hash", "")
        e.capabilities = raw.get("capabilities", {})
        e.sandbox = raw.get("sandbox", {})
        e.memory = raw.get("memory", {})
        e.trust = raw.get("trust", {})
        e.envelope_hash = raw.get("envelope_hash", "")
        e.proof = raw.get("proof")
        return e
