# A2A Exchange Example

This folder shows a small Agent-to-Agent passport exchange pattern for A2A-style message flows.

## What this example demonstrates

- Agent B sends a signed passport artifact along with capability assertion
- Agent A validates schema and signature before accepting tasks
- Work receipt references an exchange id for traceability

## Files

- `a2a_passport_exchange.go` — mock A2A request/reply with passport payload

## Run

```bash
cd standard/examples/a2a-exchange
go run a2a_passport_exchange.go
```
