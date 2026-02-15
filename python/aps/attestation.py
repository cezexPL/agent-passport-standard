"""Attestation exchange — W3C Verifiable Credential based attestations."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .crypto import canonicalize_json, ed25519_sign, ed25519_verify


@dataclass
class Attestation:
    context: list[str] = field(default_factory=lambda: [
        "https://www.w3.org/2018/credentials/v1",
        "https://agentpassport.org/v0.2/attestation",
    ])
    type: list[str] = field(default_factory=lambda: ["VerifiableCredential", "AgentAttestation"])
    issuer: str = ""
    issuance_date: str = ""
    expires_at: str = ""
    subject_id: str = ""
    subject_type: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    proof_value: str = ""
    proof_created: str = ""

    def to_dict(self, include_proof: bool = True) -> dict:
        d: dict[str, Any] = {
            "@context": self.context,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "credentialSubject": {
                "id": self.subject_id,
                "type": self.subject_type,
                "claims": self.claims,
            },
        }
        if self.expires_at:
            d["expirationDate"] = self.expires_at
        if include_proof and self.proof_value:
            d["proof"] = {
                "type": "Ed25519Signature2020",
                "created": self.proof_created,
                "verificationMethod": self.issuer + "#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": self.proof_value,
            }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Attestation:
        subj = d.get("credentialSubject", {})
        proof = d.get("proof", {})
        return cls(
            context=d.get("@context", []),
            type=d.get("type", []),
            issuer=d.get("issuer", ""),
            issuance_date=d.get("issuanceDate", ""),
            expires_at=d.get("expirationDate", ""),
            subject_id=subj.get("id", ""),
            subject_type=subj.get("type", ""),
            claims=subj.get("claims", {}),
            proof_value=proof.get("proofValue", ""),
            proof_created=proof.get("created", ""),
        )


def create_attestation(
    issuer_did: str,
    subject_did: str,
    att_type: str,
    claims: dict[str, Any],
    private_key,
    *,
    expires_at: str = "",
) -> Attestation:
    """Create a signed attestation."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    att = Attestation(
        issuer=issuer_did,
        issuance_date=now,
        expires_at=expires_at,
        subject_id=subject_did,
        subject_type=att_type,
        claims=dict(claims),
    )
    msg = canonicalize_json(att.to_dict(include_proof=False))
    att.proof_value = ed25519_sign(private_key, msg)
    att.proof_created = now
    return att


def verify_attestation(att: Attestation, public_key) -> bool:
    """Verify attestation signature and check expiry."""
    if not att.proof_value:
        return False

    # Check expiry
    if att.expires_at:
        try:
            exp = datetime.fromisoformat(att.expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                return False
        except ValueError:
            return False

    msg = canonicalize_json(att.to_dict(include_proof=False))
    return ed25519_verify(public_key, msg, att.proof_value)


class AttestationRegistry:
    """In-memory registry of trusted issuers."""

    def __init__(self):
        self._issuers: dict[str, Any] = {}

    def register_issuer(self, did: str, public_key):
        self._issuers[did] = public_key

    def remove_issuer(self, did: str):
        self._issuers.pop(did, None)

    def is_trusted(self, did: str) -> bool:
        return did in self._issuers

    def get_public_key(self, did: str):
        return self._issuers.get(did)

    def verify_from_registry(self, att: Attestation) -> bool:
        pk = self.get_public_key(att.issuer)
        if pk is None:
            raise ValueError(f"Issuer {att.issuer} not trusted")
        return verify_attestation(att, pk)
