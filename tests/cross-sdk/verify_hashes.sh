#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PASSPORT="$ROOT_DIR/examples/example-passport.json"

echo "=== Cross-SDK Hash Verification ==="
echo "Input: $PASSPORT"
echo

# Go
echo "[Go] Computing hash..."
GO_HASH=$(cd "$ROOT_DIR/go" && go run "$SCRIPT_DIR/hash_go.go" "$PASSPORT")
echo "  Go hash: $GO_HASH"

# Python
echo "[Python] Computing hash..."
PY_HASH=$(python3 "$SCRIPT_DIR/hash_python.py" "$PASSPORT")
echo "  Python hash: $PY_HASH"

# TypeScript
echo "[TypeScript] Computing hash..."
cd "$SCRIPT_DIR"
npm install --silent 2>/dev/null
TS_HASH=$(npx tsx hash_ts.ts "$PASSPORT")
echo "  TypeScript hash: $TS_HASH"

echo
echo "=== Comparison ==="

PASS=true
if [ "$GO_HASH" != "$PY_HASH" ]; then
  echo "FAIL: Go != Python"
  PASS=false
fi
if [ "$GO_HASH" != "$TS_HASH" ]; then
  echo "FAIL: Go != TypeScript"
  PASS=false
fi
if [ "$PY_HASH" != "$TS_HASH" ]; then
  echo "FAIL: Python != TypeScript"
  PASS=false
fi

if [ "$PASS" = true ]; then
  echo "PASS: All 3 SDKs produce identical hash: $GO_HASH"
  exit 0
else
  echo "FAIL: Hashes differ!"
  exit 1
fi
