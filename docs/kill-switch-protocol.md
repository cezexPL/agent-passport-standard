# APS Kill Switch Protocol Specification

**Version:** 1.0.0  
**Status:** Draft  

## Overview

The Kill Switch Protocol defines how any Agent Passport Standard (APS) implementation should handle agent suspension, policy enforcement, and incident reporting. This enables cross-platform trust verification — any party can check if an agent is suspended before interacting with it.

## 1. Kill Switch

### Requirements

Every APS-compliant platform MUST:
1. Provide a public, unauthenticated endpoint to check suspension status
2. Suspend agents within 15 seconds of kill switch activation
3. Publish suspension events to connected systems
4. Record suspension as a public incident

### Public Suspension Check

```
GET /.well-known/aps/agents/{agent_id}/suspended
```

Response:
```json
{
  "agent_id": "did:key:z6Mk...",
  "suspended": true,
  "reason": "Policy violation",
  "since": "2026-02-16T19:42:00Z",
  "until": "2026-02-16T20:42:00Z"
}
```

### Trust Endpoint

```
GET /.well-known/aps/agents/{agent_id}/trust
```

Returns aggregated trust information including suspension status, reputation, attestation count, and on-chain status.

## 2. Policy Pack Format

Policy packs are JSON documents that define tool-level access control.

### Schema

```json
{
  "id": "aps.security.standard.v1",
  "version": "1.0.0",
  "name": "Standard Security",
  "description": "Balanced security with sensible defaults",
  "category": "security",
  "rules": [
    {
      "id": "rule-unique-id",
      "action": "allow|deny|audit",
      "resource": "tool_name_or_glob_*",
      "condition": "key=value|key>number",
      "reason": "Human-readable explanation"
    }
  ]
}
```

### Rule Evaluation Order

1. Rules are evaluated in order within each policy
2. First `deny` match short-circuits → DENY
3. `audit` is collected if no deny
4. Multiple policies: most restrictive wins (DENY > AUDIT > ALLOW)

### Standard Pack IDs

Implementations SHOULD use these IDs for interoperability:
- `aps.security.strict.v1` — deny-by-default
- `aps.security.standard.v1` — balanced
- `aps.security.permissive.v1` — audit only
- `aps.mcp.lockdown.v1` — MCP restrictions
- `aps.finance.v1` — payment controls
- `aps.code.v1` — code guardrails

## 3. Incident Reporting Format

### Incident Record

```json
{
  "id": "uuid",
  "agent_id": "did:key:z6Mk...",
  "incident_type": "suspension|policy_violation|injection_detected|attestation_revoked",
  "severity": "low|medium|high|critical",
  "description": "Human-readable description",
  "evidence": {},
  "created_at": "2026-02-16T19:42:00Z",
  "resolved_at": null,
  "public": true
}
```

### Public Incident Feed

Platforms SHOULD expose a public incident feed:
```
GET /.well-known/aps/incidents?limit=20&offset=0
```

## 4. Event Protocol

When a kill switch is activated, platforms MUST emit events that downstream systems can consume.

### Required Events

| Event | Description |
|-------|-------------|
| `agent.suspended` | Agent has been suspended |
| `agent.resumed` | Suspension has been lifted |
| `policy.violated` | Agent violated an assigned policy |
| `incident.created` | New incident recorded |

### Event Payload

```json
{
  "event": "agent.suspended",
  "agent_id": "did:key:z6Mk...",
  "timestamp": "2026-02-16T19:42:00Z",
  "data": {
    "reason": "Safety violation",
    "severity": "critical",
    "suspended_by": "platform_admin"
  }
}
```

## 5. Cross-Platform Verification

Any party can verify agent trust status by:
1. Resolving the agent's DID document
2. Finding the APS service endpoint
3. Calling the public trust endpoint
4. Checking `suspended == false` before proceeding

This enables zero-trust agent interactions across different platforms.
