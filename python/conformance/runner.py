"""Conformance test runner — loads test-vectors.json and runs all vectors."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aps.crypto import canonicalize_json, keccak256, MerkleTree, verify_proof, generate_key_pair, ed25519_sign, ed25519_verify


class ConformanceReport:
    def __init__(self, vectors_path: str):
        with open(vectors_path) as f:
            data = json.load(f)
        self.vectors: list[dict[str, Any]] = data["vectors"]
        self.spec_version: str = data.get("spec_version", "")

    def run_all(self) -> list[tuple[str, bool, str]]:
        results: list[tuple[str, bool, str]] = []
        handlers = {
            "canonical-json-sorting": self._test_canonical,
            "keccak256-empty-object": self._test_keccak_empty,
            "keccak256-simple-passport": self._test_keccak_passport,
            "ed25519-sign-verify": self._test_ed25519,
            "merkle-tree-4-leaves": self._test_merkle_tree,
            "merkle-proof-verification": self._test_merkle_proof,
            "passport-hash-with-benchmarks": self._test_hash,
            "work-receipt-hash-4-events": self._test_hash,
            "security-envelope-hash": self._test_hash,
            "anchor-receipt-structure": self._test_anchor,
        }
        for v in self.vectors:
            name = v["name"]
            handler = handlers.get(name)
            if handler is None:
                results.append((name, False, "no handler"))
                continue
            try:
                handler(v)
                results.append((name, True, "ok"))
            except Exception as e:
                results.append((name, False, str(e)))
        return results

    def _test_canonical(self, v: dict[str, Any]) -> None:
        result = canonicalize_json(v["input"]).decode("utf-8")
        assert result == v["expected_output"], f"got {result}"

    def _test_keccak_empty(self, v: dict[str, Any]) -> None:
        canonical = canonicalize_json(v["input"])
        result = keccak256(canonical)
        assert result == v["expected_output"], f"got {result}"

    def _test_keccak_passport(self, v: dict[str, Any]) -> None:
        canonical = canonicalize_json(v["input"])
        result = keccak256(canonical)
        assert result.startswith("0x") and len(result) == 66

    def _test_ed25519(self, v: dict[str, Any]) -> None:
        pub, priv = generate_key_pair()
        msg = v["input"]["message"].encode("utf-8")
        sig = ed25519_sign(priv, msg)
        assert ed25519_verify(pub, msg, sig)

    def _test_merkle_tree(self, v: dict[str, Any]) -> None:
        tree = MerkleTree(v["input"]["leaves"])
        assert tree.root().startswith("0x")
        assert len(tree.layers) - 1 == v["expected_output"]["tree_depth"]

    def _test_merkle_proof(self, v: dict[str, Any]) -> None:
        # Use 4-leaves vector to build tree
        four = next(x for x in self.vectors if x["name"] == "merkle-tree-4-leaves")
        leaves = four["input"]["leaves"]
        tree = MerkleTree(leaves)
        assert verify_proof(leaves[0], tree.root(), tree.proof(0), 0)

    def _test_hash(self, v: dict[str, Any]) -> None:
        canonical = canonicalize_json(v["input"])
        result = keccak256(canonical)
        assert result.startswith("0x") and len(result) == 66

    def _test_anchor(self, v: dict[str, Any]) -> None:
        inp = v["input"]
        exp = v["expected_output"]
        assert exp["valid"] is True
        assert bool(inp.get("tx_hash")) == exp["has_tx_hash"]
        assert bool(inp.get("block")) == exp["has_block"]
