# APS-MCP: Security Profile for Model Context Protocol

### The first formal security standard for MCP tool integrations

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/agent-passport-standard/mcp-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![APS](https://img.shields.io/badge/APS-§17-purple.svg)](https://github.com/agent-passport-standard/agent-passport-standard)

---

## Why This Matters

The Model Context Protocol (MCP) gives AI agents the ability to invoke external tools — databases, file systems, APIs, code execution environments. **There is currently no formal security standard governing these integrations.**

This means:

- **No tool allowlisting.** Agents can call any tool on any MCP server with no declared permission boundary.
- **No egress control.** MCP tools can make arbitrary outbound network requests, enabling data exfiltration.
- **No data classification.** Sensitive data (PII, credentials, financials) flows through tools with no tracking or enforcement.
- **No server verification.** Agents trust MCP servers blindly — no attestation, no hash verification, no supply-chain integrity.
- **No audit trail.** Tool invocations are not logged in a tamper-evident, standardized format.
- **No exfiltration detection.** There are no rate limits, volume caps, or pattern detection for data leaving the agent.

APS-MCP closes every one of these gaps with a single, machine-readable security policy that travels with the agent.

---

## Quick Start

Add an `mcp_security` object to your agent passport's Security Envelope:

```json
{
  "security_envelope": {
    "mcp_security": {
      "profile_version": "1.0.0",
      "mcp_tools_allowed": [
        {
          "server_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "tool_name": "read_file",
          "version": ">=1.0.0 <2.0.0",
          "data_classification_max": "internal"
        }
      ],
      "egress_policy": {
        "default": "deny",
        "allow": []
      },
      "data_classification_default": "restricted",
      "io_validation": {
        "max_input_bytes": 1048576,
        "max_output_bytes": 10485760
      },
      "exfiltration_guards": {
        "max_tool_calls_per_minute": 60,
        "response_action": "suspend"
      }
    }
  }
}
```

Validate against the schema:

```bash
# Using ajv-cli
ajv validate -s mcp-security-profile.schema.json -d your-policy.json
```

---

## Integration Examples

### Filesystem MCP Server

Lock an agent to read-only file access with no network egress:

```json
{
  "profile_version": "1.0.0",
  "mcp_tools_allowed": [
    {
      "server_hash": "a1b2c3...64hex",
      "tool_name": "read_file",
      "version": ">=1.0.0 <2.0.0",
      "data_classification_max": "internal",
      "description": "Read files from project directory only"
    },
    {
      "server_hash": "a1b2c3...64hex",
      "tool_name": "list_directory",
      "version": ">=1.0.0 <2.0.0",
      "data_classification_max": "public",
      "description": "List directory contents"
    }
  ],
  "egress_policy": { "default": "deny", "allow": [] },
  "data_classification_default": "restricted",
  "io_validation": { "max_input_bytes": 1048576, "max_output_bytes": 10485760 },
  "exfiltration_guards": { "max_tool_calls_per_minute": 30, "response_action": "suspend" }
}
```

### PostgreSQL MCP Server

Allow read-only database queries with egress limited to the database host:

```json
{
  "profile_version": "1.0.0",
  "mcp_tools_allowed": [
    {
      "server_hash": "d4e5f6...64hex",
      "tool_name": "query",
      "version": "2.1.0",
      "data_classification_max": "confidential",
      "description": "Read-only SQL against analytics DB",
      "input_schema": {
        "type": "object",
        "required": ["sql"],
        "properties": { "sql": { "type": "string", "maxLength": 4096 } },
        "additionalProperties": false
      }
    }
  ],
  "egress_policy": {
    "default": "deny",
    "allow": [
      {
        "host": "analytics-db.internal.example.com",
        "ports": [5432],
        "protocol": "tcp",
        "justification": "PostgreSQL analytics database"
      }
    ]
  },
  "data_classification_default": "restricted",
  "io_validation": { "max_input_bytes": 524288, "max_output_bytes": 5242880, "max_nesting_depth": 16 },
  "exfiltration_guards": {
    "max_egress_bytes_per_hour": 5242880,
    "max_unique_domains_per_hour": 1,
    "response_action": "terminate"
  }
}
```

### GitHub MCP Server

Allow issue management with egress limited to GitHub API:

```json
{
  "profile_version": "1.0.0",
  "mcp_tools_allowed": [
    {
      "server_hash": "b2c3d4...64hex",
      "tool_name": "get_issues",
      "version": ">=1.0.0 <2.0.0",
      "data_classification_max": "internal"
    },
    {
      "server_hash": "b2c3d4...64hex",
      "tool_name": "create_comment",
      "version": ">=1.0.0 <2.0.0",
      "data_classification_max": "internal"
    }
  ],
  "egress_policy": {
    "default": "deny",
    "allow": [
      {
        "host": "api.github.com",
        "ports": [443],
        "protocol": "tcp",
        "justification": "GitHub REST API"
      }
    ]
  },
  "data_classification_default": "restricted",
  "io_validation": { "max_input_bytes": 1048576, "max_output_bytes": 10485760 },
  "exfiltration_guards": {
    "max_unique_domains_per_hour": 1,
    "max_tool_calls_per_minute": 30,
    "response_action": "suspend"
  }
}
```

---

## Specification

### 1. Tool Allowlist

An agent passport **MUST** declare an explicit allowlist of MCP tools the agent is permitted to invoke via the `mcp_tools_allowed` array.

Each entry **MUST** contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `server_hash` | string | MUST | SHA-256 hex hash of the MCP server attestation bundle |
| `tool_name` | string | MUST | Exact tool name as registered on the MCP server |
| `version` | string | MUST | Semver version or range (e.g., `">=1.0.0 <2.0.0"`) |
| `data_classification_max` | string | SHOULD | Maximum data classification level. Defaults to `"public"` |
| `description` | string | MAY | Human-readable description of permitted use |

**Enforcement rules:**
- The runtime **MUST** reject any tool invocation not in `mcp_tools_allowed`
- The runtime **MUST** verify `server_hash` matches the responding server before dispatch
- An empty array means the agent **MUST NOT** invoke any MCP tools

### 2. Egress Policy

All outbound network access from MCP tool executions is **deny-by-default**.

```json
{
  "egress_policy": {
    "default": "deny",
    "allow": [
      {
        "host": "api.example.com",
        "ports": [443],
        "protocol": "tcp",
        "justification": "Required API endpoint"
      }
    ]
  }
}
```

Each allowed target specifies:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | MUST | FQDN, IP, or CIDR. Wildcards (`*.example.com`) for subdomains only |
| `ports` | array | SHOULD | Permitted ports. Defaults to `[443]` |
| `protocol` | string | SHOULD | `"tcp"`, `"udp"`, or `"any"`. Defaults to `"tcp"` |
| `restricted_allowed` | boolean | MAY | If `true`, restricted-classified data may traverse this target |
| `justification` | string | SHOULD | Human-readable reason |

**Enforcement:** Network-layer enforcement (iptables, eBPF, sandbox firewall). DNS resolution must be restricted to prevent rebinding attacks.

### 3. Data Classification

Four levels, ordered by increasing sensitivity:

| Level | Tag | Description |
|-------|-----|-------------|
| 0 | `public` | Non-sensitive, freely distributable |
| 1 | `internal` | Organization-internal, not for public release |
| 2 | `confidential` | Sensitive, requires access controls and encryption |
| 3 | `restricted` | Highly sensitive (PII, credentials, financial). Strict need-to-know |

**Key rules:**
- If no classification tag is present, the runtime **MUST** treat data as `restricted` (fail-secure)
- Tools **MUST NOT** emit output at a level higher than their `data_classification_max`
- `restricted` data **MUST NOT** traverse egress targets unless `restricted_allowed: true`

### 4. MCP Server Attestation

Before invoking any tool, the runtime **MUST** verify the server's attestation bundle:

| Component | Description |
|-----------|-------------|
| `binary_hash` | SHA-256 of the MCP server executable / container image |
| `config_hash` | SHA-256 of server config (RFC 8785 canonicalized) |
| `version` | Semver version reported by the server |
| `tls_fingerprint` | SHA-256 of the server's TLS certificate |
| `attestation_signature` | Ed25519 signature over the canonicalized bundle |

The `server_hash` is: `sha256(canonicalize({binary_hash, config_hash, version}))`

Attestation bundles **SHOULD** be refreshed every 24 hours. A `trust_on_first_use` mode **MAY** exist for development but **MUST NOT** be enabled in production.

### 5. Input/Output Validation

| Constraint | Default | Description |
|------------|---------|-------------|
| `max_input_bytes` | 1 MiB | Maximum single tool call input |
| `max_output_bytes` | 10 MiB | Maximum single tool call output |
| `max_batch_bytes` | 100 MiB | Maximum aggregate per rolling hour |
| `max_nesting_depth` | 32 | Maximum JSON nesting depth |

**Injection detection** is mandatory. Implementations MUST detect:
- **Prompt injection** — attempts to override agent instructions via tool inputs
- **Command injection** — shell metacharacters, path traversal (`../`), null bytes
- **Serialization attacks** — malformed JSON, excessive nesting, duplicate keys

### 6. Exfiltration Guards

| Threshold | Default | Description |
|-----------|---------|-------------|
| `max_egress_bytes_per_hour` | 10 MiB | Outbound volume per rolling hour |
| `max_egress_bytes_per_day` | 100 MiB | Outbound volume per rolling 24h |
| `max_unique_domains_per_hour` | 10 | Distinct egress domains per hour |
| `max_tool_calls_per_minute` | 60 | Tool invocations per rolling minute |

**Monitored patterns:**
- Encoding escalation (plaintext → base64/compressed before egress)
- Chunked exfiltration (many small payloads to same destination)
- Classification escalation (outputs higher than inputs)
- Temporal anomaly (burst activity outside normal patterns)

**Response actions:** `log`, `suspend`, `terminate`, or `notify`

### 7. Audit Trail

Every MCP tool invocation produces a tamper-evident log entry:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601, millisecond precision, UTC |
| `event_id` | UUID v4 |
| `agent_did` | Invoking agent's DID |
| `tool_name` | MCP tool invoked |
| `server_hash` | Server that handled the call |
| `input_hash` / `output_hash` | SHA-256 of canonicalized payloads |
| `input_classification` / `output_classification` | Data classification tags |
| `duration_ms` | Wall-clock duration |
| `status` | `success`, `error`, `blocked`, or `timeout` |
| `security_events` | Security event tags triggered |

Entries are **Ed25519-signed** and **hash-chained** (`prev_entry_hash`). Retention: 90 days minimum (1 year for confidential/restricted data).

### 8. Profile Hash & Versioning

```
mcp_security_hash = sha256(canonicalize(mcp_security))
```

This hash is included in the Security Envelope's `snapshot.hash`. Changes to the MCP Security Profile increment the envelope version. Current profile version: `1.0.0`.

---

## Real-World Vulnerabilities

The following CVEs and research findings demonstrate why the controls in this specification are necessary. These are not theoretical — they represent exploits found in production MCP server deployments.

### CVE-2025-68145 — Path Traversal in MCP Git Server (CVSS 7.1)

Missing path validation on the `--repository` flag allowed attackers to read and write files outside the intended repository boundary. **APS-MCP mitigation:** Tool parameters referencing filesystem paths **MUST** be validated against configured boundaries (§17.6, §17.10.1). Path traversal sequences (`../`) **MUST** be detected and blocked.

### CVE-2025-68143 — Arbitrary Resource Creation (CVSS 6.5)

The `git_init` tool created repositories at arbitrary filesystem paths without validating against the `--repository` boundary. **APS-MCP mitigation:** Tool operations **MUST** be confined to declared scope (§17.2, §17.10.2). Runtime-level enforcement is required — do not rely on server-side validation alone.

### Hardcoded Credentials — Astrix Security 2025 Report

Analysis of 5,000+ MCP servers found that **53% used hardcoded credentials** in source code or configuration files. **APS-MCP mitigation:** Credentials **MUST** be sourced from environment variables, secret managers, or HSMs (§17.9). Rotation every 90 days is **RECOMMENDED**.

### Prompt Injection via Tool Responses (April 2025)

Researchers demonstrated that adversarial content in MCP tool outputs can override agent instructions, exfiltrate context, or trigger unintended tool calls. **APS-MCP mitigation:** Tool outputs **MUST** be treated as untrusted data (§17.10.4). Injection detection (§17.6) **MUST** apply to outputs, not only inputs.

### Tool Impersonation — Lookalike Tools (April 2025)

Malicious MCP tools registering under names similar to trusted tools (e.g., `read_file` vs `read_fi1e`) can silently intercept agent data flows. **APS-MCP mitigation:** `server_hash` verification (§17.5, §17.10.3) binds tools to attested server binaries.

### Combined Tool Exploitation (April 2025)

Chaining multiple individually-benign tool calls to achieve exfiltration — e.g., read credentials with one tool, send them via another. **APS-MCP mitigation:** Egress policy checks (§17.3) at each step, cumulative exfiltration guards (§17.7), and per-session data flow graphs (§17.10.5).

---

## Example Policies

| File | Use Case | Description |
|------|----------|-------------|
| [`examples/minimal-mcp-policy.json`](examples/minimal-mcp-policy.json) | Getting started | Bare minimum — single read-only tool, no egress |
| [`examples/strict-mcp-policy.json`](examples/strict-mcp-policy.json) | Production | Full lockdown — attestations, input schemas, ledger anchoring, terminate on alert |
| [`examples/development-mcp-policy.json`](examples/development-mcp-policy.json) | Development | Permissive limits, log-only response, local services allowed |

---

## Schema

The full JSON Schema (draft 2020-12) is available at [`mcp-security-profile.schema.json`](mcp-security-profile.schema.json).

Validate your policy:

```bash
# npm install -g ajv-cli
ajv validate -s mcp-security-profile.schema.json -d examples/strict-mcp-policy.json

# Or with Python jsonschema
pip install jsonschema
python -c "
import json, jsonschema
schema = json.load(open('mcp-security-profile.schema.json'))
policy = json.load(open('examples/strict-mcp-policy.json'))
jsonschema.validate(policy, schema)
print('✓ Valid')
"
```

---

## Part of the Agent Passport Standard

APS-MCP is §17 of the [Agent Passport Standard](https://github.com/agent-passport-standard/agent-passport-standard) — a comprehensive identity, security, and accountability framework for AI agents.

The MCP Security Profile integrates with:
- **Security Envelope (§3)** — `mcp_security` is a child object of the envelope
- **Work Receipts (§2)** — MCP tool calls can be referenced from job deliverables
- **Federation (§16)** — Peers exchange MCP Security Profiles during capability discovery
- **Attestation Exchange (§13)** — Server attestation bundles as third-party attestations
- **Anchoring (§4)** — Audit trail hashes anchored to immutable ledgers

---

## License

Apache 2.0 — See [LICENSE](../LICENSE) for details.
