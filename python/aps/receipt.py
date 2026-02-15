"""Work Receipt artifact."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import crypto


@dataclass
class ReceiptConfig:
    receipt_id: str
    job_id: str
    agent_did: str
    client_did: str
    agent_snapshot: dict[str, Any]
    platform_did: str = ""


class WorkReceipt:
    def __init__(self) -> None:
        self.context: str = ""
        self.spec_version: str = ""
        self.type: str = ""
        self.receipt_id: str = ""
        self.job_id: str = ""
        self.agent_did: str = ""
        self.client_did: str = ""
        self.platform_did: str = ""
        self.agent_snapshot: dict[str, Any] = {}
        self.events: list[dict[str, Any]] = []
        self.batch_proof: dict[str, Any] | None = None
        self.receipt_hash: str = ""
        self.proof: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "@context": self.context,
            "spec_version": self.spec_version,
            "type": self.type,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "agent_did": self.agent_did,
            "client_did": self.client_did,
            "agent_snapshot": self.agent_snapshot,
            "events": self.events,
            "receipt_hash": self.receipt_hash,
        }
        if self.platform_did:
            d["platform_did"] = self.platform_did
        if self.batch_proof is not None:
            d["batch_proof"] = self.batch_proof
        if self.proof is not None:
            d["proof"] = self.proof
        return d

    @staticmethod
    def new(cfg: ReceiptConfig) -> "WorkReceipt":
        if not cfg.receipt_id or not cfg.job_id:
            raise ValueError("receipt_id and job_id are required")
        if not cfg.agent_did or not cfg.client_did:
            raise ValueError("agent_did and client_did are required")

        r = WorkReceipt()
        r.context = "https://agentpassport.org/v0.1"
        r.spec_version = "0.1.0"
        r.type = "WorkReceipt"
        r.receipt_id = cfg.receipt_id
        r.job_id = cfg.job_id
        r.agent_did = cfg.agent_did
        r.client_did = cfg.client_did
        r.platform_did = cfg.platform_did
        r.agent_snapshot = cfg.agent_snapshot
        r.events = []
        return r

    def add_event(self, event: dict[str, Any]) -> None:
        if not event.get("type"):
            raise ValueError("event type is required")
        if not event.get("timestamp"):
            event["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.events.append(event)

    def hash(self) -> str:
        return crypto.hash_excluding_fields(self.to_dict(), "proof", "receipt_hash")

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        self.receipt_hash = self.hash()
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

    def validate(self) -> None:
        from aps.validate import validate_receipt
        validate_receipt(self.to_dict())

    @staticmethod
    def from_json(data: bytes | str, validate: bool = True) -> "WorkReceipt":
        raw = json.loads(data)
        if validate:
            from aps.validate import validate_receipt
            validate_receipt(raw)
        r = WorkReceipt()
        r.context = raw.get("@context", "")
        r.spec_version = raw.get("spec_version", "")
        r.type = raw.get("type", "")
        r.receipt_id = raw.get("receipt_id", "")
        r.job_id = raw.get("job_id", "")
        r.agent_did = raw.get("agent_did", "")
        r.client_did = raw.get("client_did", "")
        r.platform_did = raw.get("platform_did", "")
        r.agent_snapshot = raw.get("agent_snapshot", {})
        r.events = raw.get("events", [])
        r.batch_proof = raw.get("batch_proof")
        r.receipt_hash = raw.get("receipt_hash", "")
        r.proof = raw.get("proof")
        return r
