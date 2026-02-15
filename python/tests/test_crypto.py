"""Tests for crypto primitives."""
from aps.crypto import (
    canonicalize_json, keccak256, ed25519_sign, ed25519_verify,
    generate_key_pair, MerkleTree, verify_proof,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_canonical_json_sorting():
    obj = {"z": 1, "a": 2, "m": 3}
    assert canonicalize_json(obj) == b'{"a":2,"m":3,"z":1}'


def test_canonical_json_nested():
    obj = {"b": {"z": 1, "a": 2}, "a": 1}
    assert canonicalize_json(obj) == b'{"a":1,"b":{"a":2,"z":1}}'


def test_keccak256_empty_object():
    result = keccak256(b"{}")
    assert result == "0xb48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d"


def test_ed25519_sign_verify_roundtrip():
    pub, priv = generate_key_pair()
    msg = b"hello world"
    sig = ed25519_sign(priv, msg)
    assert ed25519_verify(pub, msg, sig)
    assert not ed25519_verify(pub, b"wrong", sig)


def test_merkle_tree_4_leaves():
    leaves = [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000003",
        "0x0000000000000000000000000000000000000000000000000000000000000004",
    ]
    tree = MerkleTree(leaves)
    root = tree.root()
    assert root.startswith("0x")
    assert len(root) == 66  # 0x + 64 hex chars
    # depth = 2 (4 leaves → 2 levels of hashing)
    assert len(tree.layers) == 3  # leaves + 1 intermediate + root


def test_merkle_proof_verification():
    leaves = [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000003",
        "0x0000000000000000000000000000000000000000000000000000000000000004",
    ]
    tree = MerkleTree(leaves)
    root = tree.root()
    for i in range(4):
        proof = tree.proof(i)
        assert verify_proof(leaves[i], root, proof, i)
    # Bad proof
    assert not verify_proof(leaves[0], "0x" + "ff" * 32, tree.proof(0), 0)
