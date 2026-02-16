"""§18 Provenance types for the Agent Passport Standard."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Provenance:
    model_digest: str = ""
    toolchain_digest: str = ""
    prompt_template_hash: str = ""
    policy_hash: str = ""
    runtime_version: str = ""
    parent_receipt_ids: list[str] = field(default_factory=list)
    pipeline_id: str = ""
    step_index: int = 0
    watermark: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "modelDigest": self.model_digest,
            "toolchainDigest": self.toolchain_digest,
            "promptTemplateHash": self.prompt_template_hash,
            "policyHash": self.policy_hash,
            "runtimeVersion": self.runtime_version,
            "parentReceiptIds": self.parent_receipt_ids,
            "pipelineId": self.pipeline_id,
            "stepIndex": self.step_index,
            "watermark": self.watermark,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Provenance:
        return cls(
            model_digest=raw.get("modelDigest", ""),
            toolchain_digest=raw.get("toolchainDigest", ""),
            prompt_template_hash=raw.get("promptTemplateHash", ""),
            policy_hash=raw.get("policyHash", ""),
            runtime_version=raw.get("runtimeVersion", ""),
            parent_receipt_ids=raw.get("parentReceiptIds", []),
            pipeline_id=raw.get("pipelineId", ""),
            step_index=raw.get("stepIndex", 0),
            watermark=raw.get("watermark", ""),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.step_index < 0:
            errors.append("step_index must be >= 0")
        return errors
