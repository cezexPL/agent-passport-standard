"""Tests for §17 MCP Security Profile."""
import pytest
from aps.mcp import MCPSecurityProfile, ToolAllowEntry, EgressPolicy, AuditEntry


def _sample_profile() -> MCPSecurityProfile:
    return MCPSecurityProfile(
        tool_allowlist=[
            ToolAllowEntry(name="web_search", description="Search the web", max_calls_per_session=10),
            ToolAllowEntry(name="file_read"),
        ],
        egress_policy=EgressPolicy(default_deny=True, allowed_domains=["api.example.com"]),
        data_classification="confidential",
        server_attestation="sha256:abc123",
        validation_rules=["no-pii-leak"],
        exfiltration_guards=["token-scanner"],
        audit_config=[AuditEntry(event="tool_call", timestamp="2025-01-01T00:00:00Z", actor="agent-1")],
    )


class TestToolAllowEntry:
    def test_round_trip(self):
        t = ToolAllowEntry(name="x", description="desc", parameters_schema={"type": "object"}, max_calls_per_session=5)
        d = t.to_dict()
        assert d["name"] == "x"
        assert d["parametersSchema"] == {"type": "object"}
        assert d["maxCallsPerSession"] == 5
        t2 = ToolAllowEntry.from_dict(d)
        assert t2 == t

    def test_minimal(self):
        t = ToolAllowEntry(name="y")
        d = t.to_dict()
        assert "parametersSchema" not in d
        assert "maxCallsPerSession" not in d


class TestEgressPolicy:
    def test_default_deny(self):
        e = EgressPolicy()
        assert e.default_deny is True
        assert e.to_dict()["defaultDeny"] is True

    def test_round_trip(self):
        e = EgressPolicy(default_deny=False, allowed_domains=["a.com"], allowed_ips=["1.2.3.4"])
        e2 = EgressPolicy.from_dict(e.to_dict())
        assert e2 == e


class TestAuditEntry:
    def test_round_trip(self):
        a = AuditEntry(event="e", timestamp="t", actor="a", detail="d")
        a2 = AuditEntry.from_dict(a.to_dict())
        assert a2 == a


class TestMCPSecurityProfile:
    def test_round_trip(self):
        p = _sample_profile()
        d = p.to_dict()
        p2 = MCPSecurityProfile.from_dict(d)
        assert p2.to_dict() == d

    def test_camel_case_keys(self):
        p = _sample_profile()
        d = p.to_dict()
        assert "toolAllowlist" in d
        assert "egressPolicy" in d
        assert "dataClassification" in d
        assert "serverAttestation" in d
        assert "validationRules" in d
        assert "exfiltrationGuards" in d
        assert "auditConfig" in d

    def test_validate_ok(self):
        p = _sample_profile()
        assert p.validate() == []

    def test_validate_bad_classification(self):
        p = MCPSecurityProfile(data_classification="top-secret")
        errors = p.validate()
        assert any("data_classification" in e for e in errors)

    def test_validate_empty_tool_name(self):
        p = MCPSecurityProfile(tool_allowlist=[ToolAllowEntry(name="")])
        errors = p.validate()
        assert any("name is required" in e for e in errors)

    def test_validate_negative_max_calls(self):
        p = MCPSecurityProfile(tool_allowlist=[ToolAllowEntry(name="x", max_calls_per_session=-1)])
        errors = p.validate()
        assert any("max_calls_per_session" in e for e in errors)

    def test_validate_audit_missing_fields(self):
        p = MCPSecurityProfile(audit_config=[AuditEntry(event="", timestamp="")])
        errors = p.validate()
        assert len(errors) == 2

    def test_defaults(self):
        p = MCPSecurityProfile()
        assert p.data_classification == "internal"
        assert p.egress_policy.default_deny is True
