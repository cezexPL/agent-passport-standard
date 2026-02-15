# Contributing to Agent Passport Standard (APS)

Thank you for your interest in contributing to the Agent Passport Standard!

## How to Contribute

### 1. Fork & Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR-USERNAME/agent-passport-standard.git
cd agent-passport-standard
```

### 2. Create a Branch

```bash
git checkout -b feature/my-improvement
```

### 3. Make Changes

- **Spec changes** → edit files in `spec/`
- **Go SDK** → edit files in `go/`
- **Python SDK** → edit files in `python/`
- **TypeScript SDK** → edit files in `typescript/`

### 4. Run Tests (ALL 3 SDKs)

Any change to the spec or one SDK must be reflected in **all 3 SDKs**:

```bash
# Go
cd go && go test ./... && go test ./conformance -v

# Python
cd python && pip install pycryptodome cryptography jsonschema && python -m pytest tests/ -v

# TypeScript
cd typescript && npm install && npx vitest run
```

### 5. Submit a Pull Request

```bash
git push origin feature/my-improvement
```

Then open a Pull Request on GitHub. Fill in the PR template.

**All PRs require:**
- ✅ All 3 SDK tests passing (CI will check automatically)
- ✅ Review and approval from a maintainer (@cezexPL)
- ✅ PR template filled in

---

## Issues

Use GitHub Issues to report:
- **Bugs** — something doesn't work as documented
- **Spec ambiguity** — unclear wording in the specification
- **Implementation mismatch** — SDKs behave differently from the spec
- **Feature requests** — new capabilities or extensions

Include:
- Affected artifact (Passport, Work Receipt, Security Envelope)
- Sample JSON payload (if applicable)
- Expected vs actual behavior
- SDK and version used

---

## RFC Process (for breaking changes)

For breaking or versioned changes to the specification:

1. **Open an Issue** titled `RFC: <summary>` with:
   - Problem statement
   - Proposed solution
   - Examples of producer/consumer impact
2. **Discussion** — community feedback via issue comments or Discussions
3. **Consensus** — explicit approval from at least one maintainer
4. **Implementation** — PR with spec change + all 3 SDK updates + tests
5. **Merge** — maintainer reviews and merges

---

## Code Style

- **Go:** `gofmt` standard formatting
- **Python:** PEP 8 (use `black` formatter if possible)
- **TypeScript:** Prettier defaults
- **Commits:** `feat(scope): summary` / `fix(scope): summary` / `docs: summary`
- **Spec:** RFC 2119 keywords (MUST, SHOULD, MAY) in uppercase

---

## Branch Protection

The `main` branch is protected:
- **No direct pushes** — all changes via Pull Request
- **CI must pass** — Go, Python, TypeScript tests + cross-SDK conformance
- **Review required** — at least 1 approval from @cezexPL
- **No force pushes** — history is immutable
- **Stale reviews dismissed** — pushing new commits requires re-approval

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

## Questions?

- Open a [Discussion](https://github.com/cezexPL/agent-passport-standard/discussions)
- File an [Issue](https://github.com/cezexPL/agent-passport-standard/issues)

We welcome contributions from the global AI agent community. 🛂
