# APS OpenClaw Plugin — Integration Specification

## Overview

The APS (Agent Passport Standard) OpenClaw Plugin provides runtime enforcement of security policies at the `before_tool_call` hook. Every tool invocation passes through the APS policy engine before execution.

## Architecture

The plugin operates as an OpenClaw **skill** — a SKILL.md file that instructs the agent to call `check.sh` before every tool execution. The shell wrapper invokes the Node.js policy evaluator which returns an ALLOW/DENY decision.

### Enforcement Chain

```
Agent → Tool Call → check.sh → evaluator.js → Decision
                                    ├── kill-switch.js (suspend check)
                                    ├── injection-scanner.js (prompt injection)
                                    └── policy.json (rule evaluation)
```

### Exit Codes

- `0` — ALLOW (tool may proceed)
- `1` — DENY (tool must NOT execute)
- `2` — ERROR (configuration issue)

### Output Format

```json
{
  "decision": "ALLOW" | "DENY",
  "reason": "Human-readable explanation",
  "policy": "aps.security.standard.v1",
  "timestamp": "2026-02-16T19:41:00.000Z"
}
```

## §17 MCP Security Profile Integration

The plugin enforces §17 of the Agent Passport Standard for MCP (Model Context Protocol) tool calls:

1. **Server Allowlist** — Only pre-approved MCP servers may be invoked
2. **Rate Limiting** — Per-server call limits within configurable time windows
3. **Hash Verification** — Optional server identity verification (policy `aps.mcp.lockdown`)

## Identity

Each agent installation generates an Ed25519 keypair stored at `~/.aps/identity.json`. This identity:

- Uniquely identifies the agent instance
- Can sign audit log entries (future)
- Enables remote management via APS API

## Policy Engine

Policies are JSON documents with rules per tool type. The engine evaluates:

1. **Kill switch** — Immediate deny if `~/.aps/suspended` exists
2. **Injection scan** — All parameters scanned for prompt injection (severity ≥ 7 = deny)
3. **Rule matching** — First rule matching the tool name is evaluated
4. **Default action** — `allow` or `deny` when no rule matches

## Audit Trail

All decisions are logged as JSON Lines to `~/.aps/audit.log`. Configurable per-policy:
- `log_denials: true/false`
- `log_allows: true/false`

## Installation

```bash
npx @aps/openclaw-plugin
```

Or manually: copy skill files to `~/.openclaw/workspace/skills/aps-guardrail/`.

## Compatibility

- Node.js ≥ 18
- macOS and Linux
- Zero external npm dependencies
- OpenClaw skill system
