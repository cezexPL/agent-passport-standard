"""Agent Passport Bundle — aggregates passport, receipts, attestations, reputation, anchors."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import crypto
from .passport import AgentPassport
from .receipt import WorkReceipt
from .attestation import Attestation
from .reputation import ReputationSummary


@dataclass
class AgentPassportBundle:
    passport: dict[str, Any] = field(default_factory=dict)
    work_receipts: list[dict[str, Any]] = field(default_factory=list)
    attestations: list[dict[str, Any]] = field(default_factory=list)
    reputation_summary: dict[str, Any] | None = None
    anchor_proofs: list[dict[str, Any]] = field(default_factory=list)
    proof: dict[str, Any] | None = None

    def to_dict(self, include_proof: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "AgentPassportBundle",
            "passport": self.passport,
            "work_receipts": self.work_receipts,
            "attestations": self.attestations,
            "reputation_summary": self.reputation_summary,
            "anchor_proofs": self.anchor_proofs,
        }
        if include_proof and self.proof is not None:
            d["proof"] = self.proof
        return d

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        canonical = crypto.canonicalize_json(self.to_dict(include_proof=False))
        sig = crypto.ed25519_sign(private_key, canonical)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        agent_did = self.passport.get("id", "")
        self.proof = {
            "type": "Ed25519Signature2020",
            "created": now,
            "verificationMethod": agent_did + "#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": sig,
        }

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        if self.proof is None:
            return False
        canonical = crypto.canonicalize_json(self.to_dict(include_proof=False))
        return crypto.ed25519_verify(public_key, canonical, self.proof["proofValue"])

    def verify_all(self, public_key: Ed25519PublicKey) -> bool:
        """Verify bundle signature, nested passport, and all receipts."""
        if not self.verify(public_key):
            return False

        # Verify passport
        p = AgentPassport.from_json(json.dumps(self.passport), validate=False)
        if p.proof and not p.verify(public_key):
            return False

        # Verify receipts
        for r_data in self.work_receipts:
            r = WorkReceipt.from_json(json.dumps(r_data), validate=False)
            if r.proof and not r.verify(public_key):
                return False

        return True

    def to_json(self) -> bytes:
        return crypto.canonicalize_json(self.to_dict())

    @classmethod
    def from_json(cls, data: bytes | str) -> "AgentPassportBundle":
        raw = json.loads(data) if isinstance(data, (bytes, str)) else data
        return cls(
            passport=raw.get("passport", {}),
            work_receipts=raw.get("work_receipts", []),
            attestations=raw.get("attestations", []),
            reputation_summary=raw.get("reputation_summary"),
            anchor_proofs=raw.get("anchor_proofs", []),
            proof=raw.get("proof"),
        )
