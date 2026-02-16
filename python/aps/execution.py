"""§20 Execution Attestation types for the Agent Passport Standard."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ExecutionAttestation:
    envelope_hash: str = ""
    measurement: str = ""
    platform: str = ""
    nonce: str = ""
    report_signature: str = ""
    trust_level: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelopeHash": self.envelope_hash,
            "measurement": self.measurement,
            "platform": self.platform,
            "nonce": self.nonce,
            "reportSignature": self.report_signature,
            "trustLevel": self.trust_level,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ExecutionAttestation:
        return cls(
            envelope_hash=raw.get("envelopeHash", ""),
            measurement=raw.get("measurement", ""),
            platform=raw.get("platform", ""),
            nonce=raw.get("nonce", ""),
            report_signature=raw.get("reportSignature", ""),
            trust_level=raw.get("trustLevel", 0),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.trust_level < 0 or self.trust_level > 3:
            errors.append("trust_level must be between 0 and 3")
        if not self.envelope_hash:
            errors.append("envelope_hash is required")
        return errors
