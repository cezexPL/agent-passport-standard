"""Cryptographic primitives for the Agent Passport Standard v0.1."""
from __future__ import annotations

import json
from typing import Any

from Crypto.Hash import keccak as _keccak_mod
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as _Priv,
)


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785-like)
# ---------------------------------------------------------------------------

def canonicalize_json(obj: Any) -> bytes:
    """Return deterministic JSON bytes with sorted keys, no whitespace, UTF-8."""
    # Round-trip through json to normalise (handles dataclass-like objs via default)
    raw = json.loads(json.dumps(obj, default=_json_default))
    return json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_default(o: Any) -> Any:
    if hasattr(o, "__dict__"):
        return {k: v for k, v in o.__dict__.items() if not k.startswith("_")}
    raise TypeError(f"Object of type {type(o)} is not JSON serializable")


# ---------------------------------------------------------------------------
# Keccak-256
# ---------------------------------------------------------------------------

def keccak256(data: bytes) -> str:
    """Return '0x' + hex of Keccak-256 hash."""
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return "0x" + h.hexdigest()


def keccak256_bytes(data: bytes) -> bytes:
    """Return raw 32-byte Keccak-256 digest."""
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return h.digest()


def snapshot_hash(payload: Any) -> str:
    """Canonicalize payload then keccak256."""
    return keccak256(canonicalize_json(payload))


def hash_excluding_fields(obj: Any, *exclude: str) -> str:
    """Marshal obj to JSON, remove top-level keys in *exclude*, canonicalize, keccak256."""
    raw = json.loads(json.dumps(obj, default=_json_default))
    if not isinstance(raw, dict):
        raise ValueError("not an object")
    for k in exclude:
        raw.pop(k, None)
    return keccak256(canonicalize_json(raw))


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

def ed25519_sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign data, return hex-encoded signature."""
    return private_key.sign(data).hex()


def ed25519_verify(public_key: Ed25519PublicKey, data: bytes, signature_hex: str) -> bool:
    """Verify hex-encoded Ed25519 signature. Returns True/False."""
    try:
        public_key.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


def generate_key_pair() -> tuple[Ed25519PublicKey, Ed25519PrivateKey]:
    """Generate a new Ed25519 key pair."""
    priv = _Priv.generate()
    return priv.public_key(), priv


# ---------------------------------------------------------------------------
# Merkle Tree
# ---------------------------------------------------------------------------

def _hex_to_bytes(s: str) -> bytes:
    if s.startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


def _hash_pair(a: str, b: str) -> str:
    a_bytes = _hex_to_bytes(a)
    b_bytes = _hex_to_bytes(b)
    if a_bytes.hex() > b_bytes.hex():
        a_bytes, b_bytes = b_bytes, a_bytes
    return keccak256(a_bytes + b_bytes)


class MerkleTree:
    """Simple binary Merkle tree using Keccak-256 with sorted-concat pairing."""

    def __init__(self, leaves: list[str]):
        if not leaves:
            self.leaves: list[str] = []
            self.layers: list[list[str]] = []
            return

        normalized = list(leaves)
        # Pad to power of 2
        while normalized and (len(normalized) & (len(normalized) - 1)) != 0:
            normalized.append(normalized[-1])

        self.leaves = normalized
        self.layers = [list(normalized)]

        current = normalized
        while len(current) > 1:
            nxt = [_hash_pair(current[i], current[i + 1]) for i in range(0, len(current), 2)]
            self.layers.append(nxt)
            current = nxt

    def root(self) -> str:
        if not self.layers:
            return ""
        top = self.layers[-1]
        return top[0] if top else ""

    def proof(self, index: int) -> list[str]:
        if index < 0 or index >= len(self.leaves):
            return []
        result: list[str] = []
        idx = index
        for i in range(len(self.layers) - 1):
            layer = self.layers[i]
            if idx % 2 == 0:
                if idx + 1 < len(layer):
                    result.append(layer[idx + 1])
            else:
                result.append(layer[idx - 1])
            idx //= 2
        return result


def verify_proof(leaf: str, root: str, proof: list[str], index: int) -> bool:
    """Verify a Merkle inclusion proof."""
    current = leaf
    idx = index
    for sibling in proof:
        if idx % 2 == 0:
            current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
        idx //= 2
    return current == root
