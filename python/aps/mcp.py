"""§17 MCP Security Profile types for the Agent Passport Standard."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


def _to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _dict_to_camel(d: dict[str, Any]) -> dict[str, Any]:
    return {_to_camel(k): v for k, v in d.items()}


def _dict_from_camel(d: dict[str, Any]) -> dict[str, Any]:
    import re
    def _to_snake(s: str) -> str:
        return re.sub(r'([A-Z])', r'_\1', s).lower().lstrip('_')
    return {_to_snake(k): v for k, v in d.items()}


@dataclass
class ToolAllowEntry:
    name: str
    description: str = ""
    parameters_schema: dict[str, Any] | None = None
    max_calls_per_session: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name}
        if self.description:
            d["description"] = self.description
        if self.parameters_schema is not None:
            d["parametersSchema"] = self.parameters_schema
        if self.max_calls_per_session is not None:
            d["maxCallsPerSession"] = self.max_calls_per_session
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ToolAllowEntry:
        return cls(
            name=raw["name"],
            description=raw.get("description", ""),
            parameters_schema=raw.get("parametersSchema"),
            max_calls_per_session=raw.get("maxCallsPerSession"),
        )


@dataclass
class EgressPolicy:
    default_deny: bool = True
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "defaultDeny": self.default_deny,
            "allowedDomains": self.allowed_domains,
            "allowedIps": self.allowed_ips,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EgressPolicy:
        return cls(
            default_deny=raw.get("defaultDeny", True),
            allowed_domains=raw.get("allowedDomains", []),
            allowed_ips=raw.get("allowedIps", []),
        )


@dataclass
class AuditEntry:
    event: str
    timestamp: str
    actor: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"event": self.event, "timestamp": self.timestamp}
        if self.actor:
            d["actor"] = self.actor
        if self.detail:
            d["detail"] = self.detail
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AuditEntry:
        return cls(
            event=raw["event"],
            timestamp=raw["timestamp"],
            actor=raw.get("actor", ""),
            detail=raw.get("detail", ""),
        )


@dataclass
class MCPSecurityProfile:
    tool_allowlist: list[ToolAllowEntry] = field(default_factory=list)
    egress_policy: EgressPolicy = field(default_factory=EgressPolicy)
    data_classification: str = "internal"
    server_attestation: str = ""
    validation_rules: list[str] = field(default_factory=list)
    exfiltration_guards: list[str] = field(default_factory=list)
    audit_config: list[AuditEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "toolAllowlist": [t.to_dict() for t in self.tool_allowlist],
            "egressPolicy": self.egress_policy.to_dict(),
            "dataClassification": self.data_classification,
            "serverAttestation": self.server_attestation,
            "validationRules": self.validation_rules,
            "exfiltrationGuards": self.exfiltration_guards,
            "auditConfig": [a.to_dict() for a in self.audit_config],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> MCPSecurityProfile:
        return cls(
            tool_allowlist=[ToolAllowEntry.from_dict(t) for t in raw.get("toolAllowlist", [])],
            egress_policy=EgressPolicy.from_dict(raw.get("egressPolicy", {})),
            data_classification=raw.get("dataClassification", "internal"),
            server_attestation=raw.get("serverAttestation", ""),
            validation_rules=raw.get("validationRules", []),
            exfiltration_guards=raw.get("exfiltrationGuards", []),
            audit_config=[AuditEntry.from_dict(a) for a in raw.get("auditConfig", [])],
        )

    def validate(self) -> list[str]:
        """Return list of validation errors (empty = valid)."""
        errors: list[str] = []
        valid_classifications = {"public", "internal", "confidential", "restricted"}
        if self.data_classification not in valid_classifications:
            errors.append(f"Invalid data_classification: {self.data_classification!r}")
        for i, tool in enumerate(self.tool_allowlist):
            if not tool.name:
                errors.append(f"tool_allowlist[{i}]: name is required")
            if tool.max_calls_per_session is not None and tool.max_calls_per_session < 0:
                errors.append(f"tool_allowlist[{i}]: max_calls_per_session must be >= 0")
        for entry in self.audit_config:
            if not entry.event:
                errors.append("audit_config entry missing event")
            if not entry.timestamp:
                errors.append("audit_config entry missing timestamp")
        return errors
