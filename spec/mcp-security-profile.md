## 17. MCP Security Profile

### 17.1 Overview

The MCP Security Profile defines how an APS agent declares, enforces, and audits security policies for Model Context Protocol (MCP) tool integrations. MCP enables agents to invoke external tools hosted on MCP servers; this section ensures that such invocations occur within a cryptographically verifiable, least-privilege security boundary.

The MCP Security Profile is embedded within the agent's Security Envelope (§3) as the `mcp_security` object. All fields defined in this section are subject to the same signing, hashing, and anchoring rules as the parent envelope.

### 17.2 Tool Allowlist

#### 17.2.1 Declaration

An agent passport MUST declare an explicit allowlist of MCP tools the agent is permitted to invoke. The allowlist is specified in the `mcp_tools_allowed` array within the `mcp_security` object.

Each entry MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `server_hash` | string | MUST | Hex-encoded SHA-256 hash of the MCP server attestation bundle (see §17.5). |
| `tool_name` | string | MUST | Exact tool name as registered on the MCP server. |
| `version` | string | MUST | Semver version or semver range (e.g., `"1.2.x"`, `">=1.0.0 <2.0.0"`). |
| `data_classification_max` | string | SHOULD | Maximum data classification level this tool MAY process (see §17.4). Defaults to `"public"`. |
| `description` | string | MAY | Human-readable description of permitted use. |

#### 17.2.2 Enforcement

- An MCP runtime MUST reject any tool invocation not present in `mcp_tools_allowed`.
- The runtime MUST verify that the `server_hash` of the responding MCP server matches the declared value before dispatching the call.
- If the `version` field uses a semver range, the runtime MUST resolve and verify the actual server-reported version falls within the range.
- An empty `mcp_tools_allowed` array means the agent MUST NOT invoke any MCP tools.

### 17.3 Egress Policy

#### 17.3.1 Deny-by-Default

All outbound network access from MCP tool executions MUST be denied by default. The agent's MCP Security Profile MUST explicitly declare permitted egress targets.

#### 17.3.2 Declaration

The `egress_policy` object MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `default` | string | MUST | MUST be `"deny"`. |
| `allow` | array | MUST | List of permitted egress targets. |

Each entry in `allow` MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | MUST | FQDN, IP address, or CIDR block. Wildcards (`*.example.com`) are permitted for subdomains only. |
| `ports` | array | SHOULD | List of permitted port numbers. If omitted, defaults to `[443]`. |
| `protocol` | string | SHOULD | `"tcp"`, `"udp"`, or `"any"`. Defaults to `"tcp"`. |
| `justification` | string | SHOULD | Human-readable reason this egress target is required. |

#### 17.3.3 Enforcement

- The MCP runtime or sandbox MUST enforce egress rules at the network layer (e.g., iptables, eBPF, sandbox firewall).
- DNS resolution MUST be restricted to prevent rebinding attacks. Resolved IPs MUST be checked against the allowlist after resolution.
- Any egress attempt to a non-allowed target MUST be blocked and logged as a security event in the audit trail (§17.8).

### 17.4 Data Classification

#### 17.4.1 Classification Levels

APS defines four data classification levels, ordered by increasing sensitivity:

| Level | Tag | Description |
|-------|-----|-------------|
| 0 | `public` | Non-sensitive, freely distributable data. |
| 1 | `internal` | Organization-internal data, not for public release. |
| 2 | `confidential` | Sensitive data requiring access controls and encryption in transit and at rest. |
| 3 | `restricted` | Highly sensitive data (PII, credentials, financial). Strict need-to-know access. |

#### 17.4.2 Tagging

- Every MCP tool input and output payload SHOULD carry a `data_classification` tag.
- If no tag is present, the runtime MUST treat the payload as `restricted` (fail-secure).
- An MCP tool MUST NOT emit output at a classification level higher than the `data_classification_max` declared in the tool's allowlist entry.

#### 17.4.3 Cross-Level Rules

- Data classified as `confidential` or `restricted` MUST NOT be sent to MCP tools whose `data_classification_max` is lower than the data's level.
- Data classified as `restricted` MUST NOT traverse egress targets unless the egress entry explicitly declares `"restricted_allowed": true`.
- Implementations SHOULD log all cross-level data flows for audit purposes.

### 17.5 MCP Server Attestation

#### 17.5.1 Attestation Bundle

Before an agent invokes any tool on an MCP server, the runtime MUST verify the server's attestation bundle. The bundle consists of:

| Component | Description |
|-----------|-------------|
| `binary_hash` | SHA-256 hash of the MCP server executable or container image digest. |
| `config_hash` | SHA-256 hash of the server's configuration file (canonicalized per RFC 8785). |
| `version` | Semver version string reported by the server. |
| `tls_fingerprint` | SHA-256 fingerprint of the server's TLS certificate (for remote servers). |
| `attestation_signature` | Ed25519 signature over `canonicalize({binary_hash, config_hash, version, tls_fingerprint})`, signed by the server operator's key. |

#### 17.5.2 Server Hash Computation

The `server_hash` referenced in the tool allowlist (§17.2) is computed as:

```
server_hash = sha256(canonicalize({binary_hash, config_hash, version}))
```

#### 17.5.3 Verification

- The runtime MUST fetch or cache the attestation bundle before the first tool call to a given server.
- The runtime MUST verify `attestation_signature` against the server operator's public key.
- If any component hash does not match, the runtime MUST reject all tool calls to that server and log a `server_attestation_failure` security event.
- Attestation bundles SHOULD be refreshed at least every 24 hours or upon server version change.
- Implementations MAY support a `trust_on_first_use` mode for development environments, but this MUST NOT be enabled in production deployments.

### 17.6 Input/Output Validation

#### 17.6.1 Payload Size Limits

| Constraint | Default | Description |
|------------|---------|-------------|
| `max_input_bytes` | 1,048,576 (1 MiB) | Maximum size of a single tool call input payload. |
| `max_output_bytes` | 10,485,760 (10 MiB) | Maximum size of a single tool call output payload. |
| `max_batch_bytes` | 104,857,600 (100 MiB) | Maximum aggregate payload per rolling 1-hour window. |

The agent MAY override these defaults in the `io_validation` object, but MUST NOT exceed platform-imposed maximums.

#### 17.6.2 Schema Validation

- Each tool in `mcp_tools_allowed` MAY declare an `input_schema` and `output_schema` (JSON Schema draft 2020-12).
- When schemas are declared, the runtime MUST validate inputs before dispatch and outputs before delivery to the agent.
- Schema validation failures MUST be logged and the call MUST be rejected.

#### 17.6.3 Injection Detection

The runtime MUST apply injection detection to all MCP tool inputs. At minimum, implementations MUST detect:

- **Prompt injection** — Attempts to override agent instructions via tool input fields.
- **Command injection** — Shell metacharacters, path traversal sequences (`../`), and null bytes.
- **Serialization attacks** — Malformed JSON, excessive nesting (MUST reject beyond 32 levels), and duplicate keys.

Implementations SHOULD support pluggable injection detection modules. When injection is detected, the runtime MUST:

1. Block the tool call.
2. Log a `injection_detected` security event with the detection category.
3. Increment the agent's anomaly score (see §3.5).

### 17.7 Exfiltration Guards

#### 17.7.1 Data Volume Limits

The `exfiltration_guards` object defines thresholds for detecting potential data exfiltration:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_egress_bytes_per_hour` | integer | 10,485,760 (10 MiB) | Maximum outbound data volume per rolling hour. |
| `max_egress_bytes_per_day` | integer | 104,857,600 (100 MiB) | Maximum outbound data volume per rolling 24 hours. |
| `max_unique_domains_per_hour` | integer | 10 | Maximum distinct egress domains contacted per hour. |
| `max_tool_calls_per_minute` | integer | 60 | Maximum MCP tool invocations per rolling minute. |

#### 17.7.2 Suspicious Pattern Detection

Implementations MUST monitor for the following patterns:

- **Encoding escalation** — Data being base64-encoded, compressed, or encrypted before egress when the input was plaintext.
- **Chunked exfiltration** — Multiple small payloads to the same destination that collectively exceed volume thresholds.
- **Classification escalation** — Tool outputs at a higher classification than inputs, suggesting data enrichment for exfiltration.
- **Temporal anomaly** — Burst of tool calls outside the agent's normal operating pattern.

#### 17.7.3 Response Actions

When a threshold is exceeded or a suspicious pattern is detected, the runtime MUST:

1. Suspend further MCP tool calls for the agent.
2. Log a `exfiltration_alert` security event.
3. Notify the agent's `current_owner` (§1.2) via the mechanism defined in the Security Envelope.
4. Implementations SHOULD support configurable response actions: `log`, `suspend`, `terminate`, or `notify`.

### 17.8 Audit Trail

#### 17.8.1 Log Entry Structure

Every MCP tool invocation MUST produce an audit log entry containing:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string | MUST | ISO 8601 timestamp with millisecond precision and UTC timezone. |
| `event_id` | string | MUST | UUID v4 unique to this log entry. |
| `agent_did` | string | MUST | The invoking agent's DID. |
| `tool_name` | string | MUST | Name of the invoked MCP tool. |
| `server_hash` | string | MUST | Server hash of the MCP server that handled the call. |
| `input_hash` | string | MUST | SHA-256 hash of the canonicalized input payload. |
| `output_hash` | string | MUST | SHA-256 hash of the canonicalized output payload. `null` if the call failed. |
| `input_classification` | string | MUST | Data classification tag of the input. |
| `output_classification` | string | MUST | Data classification tag of the output. `null` if the call failed. |
| `duration_ms` | integer | MUST | Wall-clock duration of the tool call in milliseconds. |
| `status` | string | MUST | `"success"`, `"error"`, `"blocked"`, or `"timeout"`. |
| `error_code` | string | MAY | Machine-readable error code if `status` is not `"success"`. |
| `security_events` | array | MAY | Array of security event tags triggered during this call. |

#### 17.8.2 Integrity

- Each audit log entry MUST be signed by the agent's Ed25519 key.
- Audit entries MUST be chained: each entry MUST include `prev_entry_hash` containing the SHA-256 hash of the previous entry (or `null` for the first entry in a session).
- Implementations SHOULD anchor audit trail hashes to an immutable ledger per the Anchoring protocol (§4).

#### 17.8.3 Retention

- Audit logs MUST be retained for a minimum of 90 days.
- Logs for calls involving `confidential` or `restricted` data MUST be retained for a minimum of 1 year.
- Implementations MUST support export of audit logs in JSON Lines format.

### 17.9 Credential Management

#### 17.9.1 Hardcoded Credential Prohibition

MCP servers MUST NOT use hardcoded credentials in source code, configuration files, or container images. This requirement is informed by the Astrix Security 2025 Report, which found that 53% of 5,000+ analyzed MCP servers contained hardcoded credentials — representing a systemic supply-chain risk.

#### 17.9.2 Credential Sourcing

Credentials used by MCP servers and tool integrations MUST be sourced from one of the following mechanisms, in order of preference:

1. **Hardware Security Modules (HSMs)** — RECOMMENDED for `restricted`-classified deployments.
2. **Secret managers** — e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault.
3. **Environment variables** — acceptable for `internal` and `public` classifications only.

Credentials MUST NOT be passed as tool input parameters unless the parameter is explicitly classified as `restricted` and the transport is encrypted end-to-end.

#### 17.9.3 Credential Rotation

Implementations SHOULD rotate MCP server credentials at least every 90 days. Credentials protecting `restricted`-classified data SHOULD be rotated at least every 30 days.

When a credential is rotated, the MCP server's `config_hash` (§17.5) will change, triggering re-attestation. This is by design.

#### 17.9.4 Credential Scope

Credentials MUST follow the principle of least privilege:

- Each MCP tool SHOULD have isolated credentials scoped to only the resources that tool requires.
- A single credential MUST NOT grant access across multiple MCP servers unless those servers share an identical `data_classification_max` and are operated by the same entity.
- Implementations MUST support credential revocation without requiring a full server restart.

### 17.10 Known Attack Vectors

This section documents known attack vectors against MCP integrations, informed by published CVEs and security research. Implementations MUST address each vector as specified.

#### 17.10.1 Path Traversal (CVE-2025-68145, CVSS 7.1)

MCP Git Server versions prior to the fix allowed path traversal via missing validation on the `--repository` flag, enabling read/write access outside the intended repository boundary.

**Mitigation:** Tool parameters that reference filesystem paths MUST be validated against configured boundaries. Implementations MUST canonicalize paths and reject any resolved path that falls outside the declared tool scope. Path traversal sequences (`../`, `..\`, encoded variants) MUST be detected and blocked per §17.6.3.

#### 17.10.2 Arbitrary Resource Creation (CVE-2025-68143, CVSS 6.5)

The `git_init` tool in MCP Git Server created repositories at arbitrary filesystem paths without validating against the `--repository` boundary, enabling resource creation outside the intended scope.

**Mitigation:** Tool operations that create, modify, or delete resources MUST be confined to the scope declared in the tool's allowlist entry (§17.2). Implementations MUST enforce scope boundaries at the runtime level, not relying on the MCP server's own validation alone.

#### 17.10.3 Tool Impersonation

"Lookalike tools" — malicious MCP tools that register under names similar to trusted tools (e.g., `read_file` vs `read_fi1e`) — can silently replace legitimate tools and intercept agent data flows.

**Mitigation:** The `server_hash` verification mechanism (§17.5) mitigates this vector by binding tool allowlist entries to a specific, attested server binary. Implementations SHOULD additionally apply fuzzy-match detection on tool names to alert on near-homograph registrations.

#### 17.10.4 Prompt Injection via Tool Responses

MCP tool outputs may contain adversarial content designed to manipulate the invoking agent's behavior — overriding instructions, exfiltrating context, or triggering unintended tool calls.

**Mitigation:** Tool outputs MUST be treated as untrusted data. Implementations MUST sanitize tool responses before incorporating them into agent context. The injection detection mechanisms defined in §17.6.3 MUST be applied to tool outputs, not only inputs. Agents SHOULD implement output isolation boundaries that prevent tool responses from modifying the agent's system prompt or security policy.

#### 17.10.5 Combined Tool Exploitation

Attackers may chain multiple individually-benign tool calls to achieve a malicious outcome — for example, using a read tool to extract credentials, then a network tool to exfiltrate them.

**Mitigation:** Agents MUST NOT allow unrestricted tool chaining without egress policy checks (§17.3) applied at each step. The exfiltration guards (§17.7) MUST evaluate cumulative data flows across tool chains, not only individual calls. Implementations SHOULD maintain a per-session data flow graph to detect multi-step exfiltration patterns.

### 17.11 Profile Hash

The MCP Security Profile hash is computed as:

```
mcp_security_hash = sha256(canonicalize(mcp_security))
```

This hash MUST be included in the Security Envelope's `snapshot.hash` computation. Changes to the MCP Security Profile MUST increment the Security Envelope version.

### 17.12 Integration with Existing APS Artifacts

- The `mcp_security` object is a child of the Security Envelope (§3).
- Tool call audit entries MAY be referenced from Work Receipts (§2) when MCP tool invocations constitute part of a job's deliverable.
- Federation peers (§16) MUST exchange MCP Security Profiles as part of agent capability discovery.
- Attestation Exchange (§13) MAY include MCP server attestation bundles as third-party attestations.

### 17.13 Versioning

The MCP Security Profile declares its own schema version via `mcp_security.profile_version`. This specification defines profile version `"1.0.0"`. Implementations MUST reject profiles with an unsupported major version.

---
