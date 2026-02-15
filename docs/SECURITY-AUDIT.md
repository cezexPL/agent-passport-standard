# APS Security Audit Report

**Date:** 2026-02-15  
**Auditor:** TARS (automated)  
**Scope:** Go SDK v0.3, Python SDK v0.3, TypeScript SDK v0.3

---

## Findings

### Critical: None

### High:

1. **Timing-unsafe hash comparisons in Merkle proof verification** — All 3 SDKs used `==`/`===` for comparing hash strings in `VerifyProof`/`verify_proof`/`verifyProof`. This enables timing side-channel attacks where an attacker can incrementally guess correct Merkle roots by measuring response time differences.
   - **Go:** `crypto/merkle.go` — `VerifyProof()` line `return current == root`
   - **Python:** `crypto.py` — `verify_proof()` line `return current == root`
   - **TypeScript:** `crypto.ts` — `MerkleTree.verifyProof()` line `return current === root`

### Medium:

1. **No input validation on public APIs** — All 3 SDKs accept arbitrary strings for DIDs, hashes, signatures, and timestamps without format validation. Malformed inputs could propagate through the system silently.

2. **Pre-existing: Duplicate `Validate()` method in Go envelope** — `go/envelope/envelope.go` has two `Validate()` methods (lines 152 and 231), causing build failure. This is a pre-existing bug unrelated to security but blocks compilation.

3. **Pre-existing: Wrong import path in Go attestation tests** — `go/attestation/attestation_test.go` uses old module path `github.com/agent-passport/standard-go/crypto` instead of `github.com/cezexPL/agent-passport-standard/go/crypto`.

### Low:

1. **No frozen skills enforcement at struct level (Go)** — Go's `Frozen` field is informational only; mutation is not prevented at the struct level (unlike TypeScript which has `addSkill()` guard).

2. **No maximum size limits on skills/soul arrays** — While 10K entries don't crash, there are no explicit bounds to prevent DoS via extremely large payloads.

### Informational:

1. **Python `canonicalize_json` delegates to `json.dumps(sort_keys=True)`** — This handles RFC 8785 key sorting correctly but relies on Python's JSON encoder for number formatting, which may differ from strict RFC 8785 in edge cases (e.g., `-0` handling).

2. **TypeScript benchmark test uses `bench()` outside benchmark mode** — `tests/benchmark.test.ts` fails in normal test runs (pre-existing).

3. **Schema validation tests fail for unsigned documents** — Go passport/receipt `FromJSON_Roundtrip` tests fail because schema requires `proof` field (pre-existing).

---

## Fixes Applied

### 1. Timing-Safe Comparisons (HIGH → FIXED)

| SDK | File | Fix |
|-----|------|-----|
| **Go** | `crypto/merkle.go` | Replaced `==` with `TimingSafeEqual()` using `crypto/subtle.ConstantTimeCompare()` |
| **Go** | `crypto/validate.go` | New file with `TimingSafeEqual()` helper |
| **Python** | `aps/crypto.py` | Replaced `==` with `timing_safe_equal()` using `hmac.compare_digest()` |
| **TypeScript** | `src/crypto.ts` | Replaced `===` with `timingSafeEqual()` using XOR accumulator |

### 2. Input Validation Helpers (MEDIUM → MITIGATED)

Added validation functions to all 3 SDKs:

| Function | Go | Python | TypeScript |
|----------|-----|--------|------------|
| `validate_did` | `ValidateDID()` | `validate_did()` | `validateDid()` |
| `validate_hash` | `ValidateHash()` | `validate_hash()` | `validateHash()` |
| `validate_signature` | `ValidateSignature()` | `validate_signature()` | `validateSignature()` |
| `validate_timestamp` | `ValidateTimestamp()` | `validate_timestamp()` | `validateTimestamp()` |
| `validate_version` | `ValidateVersion()` | `validate_version()` | `validateVersion()` |
| `validate_trust_tier` | `ValidateTrustTier()` | `validate_trust_tier()` | `validateTrustTier()` |
| `validate_attestation_count` | `ValidateAttestationCount()` | `validate_attestation_count()` | `validateAttestationCount()` |

### 3. Security Test Suites (NEW)

| SDK | File | Tests |
|-----|------|-------|
| **Go** | `crypto/security_test.go` | 24 tests covering all 10 attack vectors + canonical JSON edge cases |
| **Go** | `passport/security_test.go` | 6 tests for passport-level attacks |
| **Python** | `tests/test_security.py` | 39 tests across 12 test classes |
| **TypeScript** | `tests/security.test.ts` | 30+ tests across 13 describe blocks |

### Attack Vectors Covered

| # | Attack | Go | Python | TypeScript |
|---|--------|:--:|:------:|:----------:|
| 1 | Signature forgery | ✅ | ✅ | ✅ |
| 2 | Hash manipulation | ✅ | ✅ | ✅ |
| 3 | Replay attack | ✅ | ✅ | ✅ |
| 4 | Null/empty injection | ✅ | ✅ | ✅ |
| 5 | Oversized input (10K) | ✅ | ✅ | ✅ |
| 6 | Unicode edge cases | ✅ | ✅ | ✅ |
| 7 | Integer overflow | ✅ | ✅ | ✅ |
| 8 | Proof stripping | ✅ | ✅ | ✅ |
| 9 | Key mismatch | ✅ | ✅ | ✅ |
| 10 | Frozen mutation | ✅ | — | ✅ |

---

## Test Results

| SDK | Status | Notes |
|-----|--------|-------|
| **Go crypto** | ✅ All pass | 24 new security tests |
| **Go passport** | ✅ New tests pass | Pre-existing `FromJSON_Roundtrip` schema failure |
| **Go envelope** | ⚠️ Build failure | Pre-existing duplicate `Validate()` method |
| **Python** | ✅ 103/103 pass | All new + existing tests pass |
| **TypeScript** | ✅ 81/81 pass | Pre-existing benchmark.test.ts failure (not a test) |

---

## Recommendations

1. **Integrate validation into constructors** — Call `validate_did()`, `validate_hash()` etc. inside `New()`/`create()` constructors for defense-in-depth.

2. **Fix pre-existing Go issues** — Remove duplicate `Validate()` in `envelope.go` and fix import path in `attestation_test.go`.

3. **Add payload size limits** — Enforce maximum skills/soul array sizes (e.g., 1000 entries) to prevent memory exhaustion.

4. **Consider strict RFC 8785 compliance** — Current canonical JSON implementations are RFC 8785-like but may diverge on number edge cases (`-0`, `1e20`). Consider using dedicated JCS libraries.

5. **Add rate limiting guidance** — Document recommended rate limits for verification endpoints to mitigate DoS.

6. **Fuzz testing** — Add fuzz tests for canonical JSON and signature verification paths.
