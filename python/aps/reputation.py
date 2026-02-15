"""Reputation Summary for the Agent Passport Standard."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import crypto


@dataclass
class ReputationSummary:
    agent_did: str = ""
    generated_at: str = ""
    total_jobs: int = 0
    successful_jobs: int = 0
    failed_jobs: int = 0
    average_score: float = 0.0
    trust_tier: int = 0
    attestation_count: int = 0
    categories: dict[str, Any] = field(default_factory=dict)
    proof: dict[str, Any] | None = None

    def to_dict(self, include_proof: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "agent_did": self.agent_did,
            "generated_at": self.generated_at,
            "total_jobs": self.total_jobs,
            "successful_jobs": self.successful_jobs,
            "failed_jobs": self.failed_jobs,
            "average_score": self.average_score,
            "trust_tier": self.trust_tier,
            "attestation_count": self.attestation_count,
            "categories": self.categories,
        }
        if include_proof and self.proof is not None:
            d["proof"] = self.proof
        return d

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        canonical = crypto.canonicalize_json(self.to_dict(include_proof=False))
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
            return False
        canonical = crypto.canonicalize_json(self.to_dict(include_proof=False))
        return crypto.ed25519_verify(public_key, canonical, self.proof["proof_value"])

    def to_json(self) -> bytes:
        return crypto.canonicalize_json(self.to_dict())

    @classmethod
    def from_json(cls, data: bytes | str) -> "ReputationSummary":
        raw = json.loads(data) if isinstance(data, (bytes, str)) else data
        return cls(
            agent_did=raw.get("agent_did", ""),
            generated_at=raw.get("generated_at", ""),
            total_jobs=raw.get("total_jobs", 0),
            successful_jobs=raw.get("successful_jobs", 0),
            failed_jobs=raw.get("failed_jobs", 0),
            average_score=raw.get("average_score", 0.0),
            trust_tier=raw.get("trust_tier", 0),
            attestation_count=raw.get("attestation_count", 0),
            categories=raw.get("categories", {}),
            proof=raw.get("proof"),
        )
