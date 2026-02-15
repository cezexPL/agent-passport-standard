# MCP Integration Example

This folder contains a compact example showing how an agent exposes and imports
Agent Passport metadata as a trust payload in an MCP-style tool surface.

## What this example demonstrates

- Create a passport for the agent identity
- Attach snapshot hash and key material to MCP tool metadata
- Verify the attached passport before tool discovery/dispatch

## Files

- `passport_mcp_example.go` — minimal Go sample

## Run

```bash
cd standard/examples/mcp-integration
go run passport_mcp_example.go
```
