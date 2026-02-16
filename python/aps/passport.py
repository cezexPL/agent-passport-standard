"""Agent Passport artifact."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import crypto


@dataclass
class Skill:
    name: str
    version: str
    description: str
    capabilities: list[str]
    hash: str
    source: str = ""


@dataclass
class Soul:
    personality: str
    work_style: str
    constraints: list[str]
    hash: str
    frozen: bool = False


@dataclass
class Policies:
    policy_set_hash: str
    summary: list[str]


@dataclass
class Lineage:
    kind: str
    parents: list[str]
    generation: int


@dataclass
class BenchmarkResult:
    score: float
    passed: bool
    suite_hash: str
    proof_hash: str
    tested_at: str


@dataclass
class Attestation:
    type: str
    issuer: str
    credential_hash: str
    issued_at: str
    expires_at: str | None = None


@dataclass
class PassportConfig:
    id: str
    public_key: str
    owner_did: str
    skills: list[Skill]
    soul: Soul
    policies: Policies
    lineage: Lineage
    evm_address: str = ""


class AgentPassport:
    """Top-level passport document."""

    def __init__(self) -> None:
        self.context: str = ""
        self.spec_version: str = ""
        self.type: str = ""
        self.id: str = ""
        self.keys: dict[str, Any] = {}
        self.genesis_owner: dict[str, Any] = {}
        self.current_owner: dict[str, Any] = {}
        self.snapshot: dict[str, Any] = {}
        self.lineage: dict[str, Any] = {}
        self.benchmarks: dict[str, Any] = {}
        self.attestations: list[dict[str, Any]] = []
        self.anchoring: dict[str, Any] | None = None
        self.proof: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "@context": self.context,
            "spec_version": self.spec_version,
            "type": self.type,
            "id": self.id,
            "keys": self.keys,
            "genesis_owner": self.genesis_owner,
            "current_owner": self.current_owner,
            "snapshot": self.snapshot,
            "lineage": self.lineage,
        }
        if self.benchmarks:
            d["benchmarks"] = self.benchmarks
        if self.attestations:
            d["attestations"] = self.attestations
        if self.anchoring is not None:
            d["anchoring"] = self.anchoring
        if self.proof is not None:
            d["proof"] = self.proof
        return d

    @staticmethod
    def new(cfg: PassportConfig) -> "AgentPassport":
        if not cfg.id:
            raise ValueError("id is required")
        if not cfg.public_key:
            raise ValueError("public_key is required")
        if not cfg.owner_did:
            raise ValueError("owner_did is required")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        p = AgentPassport()
        p.context = "https://agentpassport.org/v0.1"
        p.spec_version = "1.0.0"
        p.type = "AgentPassport"
        p.id = cfg.id

        keys: dict[str, Any] = {
            "signing": {"algorithm": "Ed25519", "public_key": cfg.public_key},
            "encryption": None,
        }
        if cfg.evm_address:
            keys["evm"] = {"address": cfg.evm_address}
        p.keys = keys

        p.genesis_owner = {"id": cfg.owner_did, "bound_at": now, "immutable": True}
        p.current_owner = {"id": cfg.owner_did, "transferred_at": None}

        skills_list = [_skill_to_dict(s) for s in cfg.skills]
        skills_obj = {"entries": skills_list, "frozen": False}
        soul_obj = {
            "personality": cfg.soul.personality,
            "work_style": cfg.soul.work_style,
            "constraints": cfg.soul.constraints,
            "hash": cfg.soul.hash,
            "frozen": cfg.soul.frozen,
        }
        policies_obj = {
            "policy_set_hash": cfg.policies.policy_set_hash,
            "summary": cfg.policies.summary,
        }

        snapshot_content = {"skills": skills_obj, "soul": soul_obj, "policies": policies_obj}
        snap_hash = crypto.snapshot_hash(snapshot_content)

        p.snapshot = {
            "version": 1,
            "hash": snap_hash,
            "prev_hash": None,
            "created_at": now,
            "skills": skills_obj,
            "soul": soul_obj,
            "policies": policies_obj,
        }

        p.lineage = {
            "kind": cfg.lineage.kind,
            "parents": cfg.lineage.parents,
            "generation": cfg.lineage.generation,
        }

        return p

    def hash(self) -> str:
        return crypto.hash_excluding_fields(self.to_dict(), "proof")

    def sign(self, private_key: Ed25519PrivateKey) -> None:
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
            "verificationMethod": self.id + "#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": sig,
        }

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        if self.proof is None:
            raise ValueError("no proof present")
        proof = self.proof
        self.proof = None
        try:
            canonical = crypto.canonicalize_json(self.to_dict())
            return crypto.ed25519_verify(public_key, canonical, proof["proofValue"])
        finally:
            self.proof = proof

    def to_json(self) -> bytes:
        return crypto.canonicalize_json(self.to_dict())

    def validate(self) -> None:
        """Validate this passport against the JSON schema. Raises ValidationError."""
        from aps.validate import validate_passport
        validate_passport(self.to_dict())

    @staticmethod
    def from_json(data: bytes | str, validate: bool = True) -> "AgentPassport":
        raw = json.loads(data)
        if validate:
            from aps.validate import validate_passport
            validate_passport(raw)
        p = AgentPassport()
        p.context = raw.get("@context", "")
        p.spec_version = raw.get("spec_version", "")
        p.type = raw.get("type", "")
        p.id = raw.get("id", "")
        p.keys = raw.get("keys", {})
        p.genesis_owner = raw.get("genesis_owner", {})
        p.current_owner = raw.get("current_owner", {})
        p.snapshot = raw.get("snapshot", {})
        p.lineage = raw.get("lineage", {})
        p.benchmarks = raw.get("benchmarks", {})
        p.attestations = raw.get("attestations", [])
        p.anchoring = raw.get("anchoring")
        p.proof = raw.get("proof")
        return p


def _skill_to_dict(s: Skill) -> dict[str, Any]:
    d: dict[str, Any] = {
        "name": s.name,
        "version": s.version,
        "description": s.description,
        "capabilities": s.capabilities,
        "hash": s.hash,
    }
    if s.source:
        d["source"] = s.source
    return d
