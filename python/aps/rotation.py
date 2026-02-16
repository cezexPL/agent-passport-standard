"""§19 Key Rotation & Identity Chain types for the Agent Passport Standard."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KeyRotation:
    old_did: str
    new_did: str
    reason: str = ""
    rotated_at: str = ""
    proof: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "oldDid": self.old_did,
            "newDid": self.new_did,
            "reason": self.reason,
            "rotatedAt": self.rotated_at,
            "proof": self.proof,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> KeyRotation:
        return cls(
            old_did=raw["oldDid"],
            new_did=raw["newDid"],
            reason=raw.get("reason", ""),
            rotated_at=raw.get("rotatedAt", ""),
            proof=raw.get("proof", ""),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.old_did:
            errors.append("old_did is required")
        if not self.new_did:
            errors.append("new_did is required")
        if self.old_did == self.new_did:
            errors.append("old_did and new_did must differ")
        return errors


@dataclass
class IdentityChain:
    rotations: list[KeyRotation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"rotations": [r.to_dict() for r in self.rotations]}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> IdentityChain:
        return cls(rotations=[KeyRotation.from_dict(r) for r in raw.get("rotations", [])])

    def current_did(self) -> str | None:
        """Return the latest DID in the chain."""
        if not self.rotations:
            return None
        return self.rotations[-1].new_did

    def original_did(self) -> str | None:
        """Return the first DID in the chain."""
        if not self.rotations:
            return None
        return self.rotations[0].old_did

    def chain_length(self) -> int:
        return len(self.rotations)

    def find_rotation(self, did: str) -> KeyRotation | None:
        """Find the rotation where did was rotated away from."""
        for r in self.rotations:
            if r.old_did == did:
                return r
        return None

    def trace(self, did: str) -> list[str]:
        """Trace forward from a DID through the chain, returning all subsequent DIDs."""
        result: list[str] = []
        current = did
        for r in self.rotations:
            if r.old_did == current:
                result.append(r.new_did)
                current = r.new_did
        return result
