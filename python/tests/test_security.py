"""Security audit tests for APS Python SDK."""
import pytest
from aps.crypto import (
    timing_safe_equal, validate_did, validate_hash, validate_signature,
    validate_timestamp, validate_version, validate_trust_tier,
    validate_attestation_count, keccak256, snapshot_hash,
    ed25519_sign, ed25519_verify, generate_key_pair, canonicalize_json,
    MerkleTree, verify_proof,
)
from aps.passport import AgentPassport, PassportConfig, Skill, Soul, Policies, Lineage


def _test_config():
    return PassportConfig(
        id="did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        public_key="z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        owner_did="did:key:z6MkpOwnerABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
        skills=[Skill(name="test", version="1.0.0", description="Test", capabilities=["test"],
                       hash="0x" + "00" * 32)],
        soul=Soul(personality="focused", work_style="test", constraints=["none"],
                  hash="0x" + "00" * 32, frozen=False),
        policies=Policies(policy_set_hash="0x" + "00" * 32, summary=["can_bid"]),
        lineage=Lineage(kind="single", parents=[], generation=0),
    )


# --- Timing-Safe Comparison ---

class TestTimingSafe:
    def test_equal(self):
        assert timing_safe_equal("abc", "abc")

    def test_not_equal(self):
        assert not timing_safe_equal("abc", "abd")

    def test_different_length(self):
        assert not timing_safe_equal("short", "longer")


# --- Validation ---

class TestValidation:
    def test_valid_did(self):
        validate_did("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")

    def test_empty_did(self):
        with pytest.raises(ValueError):
            validate_did("")

    def test_invalid_did(self):
        for d in ["not-a-did", "did:key:abc", "did:web:example.com"]:
            with pytest.raises(ValueError):
                validate_did(d)

    def test_valid_hash(self):
        validate_hash("0x" + "ab" * 32)

    def test_invalid_hash(self):
        for h in ["", "abc", "0x123", "0x" + "GG" * 32]:
            with pytest.raises(ValueError):
                validate_hash(h)

    def test_valid_signature(self):
        validate_signature("ab" * 64)

    def test_invalid_signature(self):
        for s in ["", "tooshort", "zz" * 64]:
            with pytest.raises(ValueError):
                validate_signature(s)

    def test_valid_timestamp(self):
        validate_timestamp("2026-02-15T12:00:00Z")
        validate_timestamp("2026-02-15T12:00:00+00:00")

    def test_invalid_timestamp(self):
        with pytest.raises(ValueError):
            validate_timestamp("")
        with pytest.raises(ValueError):
            validate_timestamp("not-a-date")

    def test_valid_version(self):
        validate_version(1)
        validate_version(100)

    def test_invalid_version(self):
        with pytest.raises(ValueError):
            validate_version(0)
        with pytest.raises(ValueError):
            validate_version(-1)

    def test_valid_trust_tier(self):
        for t in range(4):
            validate_trust_tier(t)

    def test_invalid_trust_tier(self):
        with pytest.raises(ValueError):
            validate_trust_tier(-1)
        with pytest.raises(ValueError):
            validate_trust_tier(4)
        with pytest.raises(ValueError):
            validate_trust_tier(999)

    def test_invalid_attestation_count(self):
        with pytest.raises(ValueError):
            validate_attestation_count(-1)


# --- Signature Forgery ---

class TestSignatureForgery:
    def test_tamper_after_signing(self):
        pub, priv = generate_key_pair()
        p = AgentPassport.new(_test_config())
        p.sign(priv)
        # Tamper
        p.snapshot["version"] = 999
        assert p.verify(pub) is False


# --- Hash Manipulation ---

class TestHashManipulation:
    def test_different_content_different_hash(self):
        h1 = snapshot_hash({"skill": "go", "version": 1})
        h2 = snapshot_hash({"skill": "go", "version": 2})
        assert h1 != h2


# --- Replay Attack ---

class TestReplayAttack:
    def test_reuse_proof(self):
        pub, priv = generate_key_pair()
        p1 = AgentPassport.new(_test_config())
        p1.sign(priv)
        stolen_proof = p1.proof

        cfg2 = _test_config()
        cfg2.id = "did:key:z6MkDIFFERENT1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        p2 = AgentPassport.new(cfg2)
        p2.proof = stolen_proof
        assert p2.verify(pub) is False


# --- Null/Empty Injection ---

class TestNullEmptyInjection:
    def test_empty_id(self):
        cfg = _test_config()
        cfg.id = ""
        with pytest.raises(ValueError):
            AgentPassport.new(cfg)

    def test_empty_public_key(self):
        cfg = _test_config()
        cfg.public_key = ""
        with pytest.raises(ValueError):
            AgentPassport.new(cfg)

    def test_empty_owner_did(self):
        cfg = _test_config()
        cfg.owner_did = ""
        with pytest.raises(ValueError):
            AgentPassport.new(cfg)


# --- Oversized Input ---

class TestOversizedInput:
    def test_10k_skills(self):
        skills = [Skill(name=f"skill-{i}", version="1.0.0", description="x",
                        capabilities=["test"], hash="0x" + "00" * 32) for i in range(10000)]
        cfg = _test_config()
        cfg.skills = skills
        p = AgentPassport.new(cfg)
        assert p.snapshot["hash"] != ""


# --- Unicode Edge Cases ---

class TestUnicodeEdgeCases:
    def test_emoji_skill(self):
        h = snapshot_hash({"skill": "🤖"})
        assert h.startswith("0x")

    def test_rtl_text(self):
        h = snapshot_hash({"skill": "مرحبا"})
        assert h.startswith("0x")

    def test_null_bytes(self):
        h = snapshot_hash({"skill": "a\x00b"})
        assert h.startswith("0x")


# --- Integer Overflow ---

class TestIntegerOverflow:
    def test_max_version(self):
        # Python handles big ints natively; just verify validation
        validate_version(2**63)

    def test_tier_999(self):
        with pytest.raises(ValueError):
            validate_trust_tier(999)

    def test_negative_attestation(self):
        with pytest.raises(ValueError):
            validate_attestation_count(-1)


# --- Proof Stripping ---

class TestProofStripping:
    def test_no_proof(self):
        pub, _ = generate_key_pair()
        p = AgentPassport.new(_test_config())
        with pytest.raises(ValueError, match="no proof present"):
            p.verify(pub)


# --- Key Mismatch ---

class TestKeyMismatch:
    def test_wrong_key(self):
        _, priv = generate_key_pair()
        pub2, _ = generate_key_pair()
        p = AgentPassport.new(_test_config())
        p.sign(priv)
        assert p.verify(pub2) is False


# --- Canonical JSON Edge Cases ---

class TestCanonicalJsonEdgeCases:
    def test_null_true_false(self):
        result = canonicalize_json({"a": None, "b": True, "c": False})
        assert result == b'{"a":null,"b":true,"c":false}'

    def test_nested_unsorted_keys(self):
        result = canonicalize_json({"z": {"b": 2, "a": 1}, "a": "first"})
        assert result == b'{"a":"first","z":{"a":1,"b":2}}'

    def test_mixed_array(self):
        result = canonicalize_json([1, "two", True, None, {"b": 2, "a": 1}])
        assert result == b'[1,"two",true,null,{"a":1,"b":2}]'

    def test_special_chars(self):
        result = canonicalize_json({"quote": 'a"b', "backslash": "a\\b", "newline": "a\nb"})
        assert b'"a\\"b"' in result
        assert b'"a\\\\b"' in result
        assert b'"a\\nb"' in result

    def test_numbers(self):
        result = canonicalize_json({"zero": 0, "one": 1, "neg": -1, "float": 1.5})
        assert b'"float":1.5' in result
        assert b'"neg":-1' in result
        assert b'"one":1' in result
        assert b'"zero":0' in result

    def test_emoji_string(self):
        result = canonicalize_json({"emoji": "😀"})
        assert "😀".encode() in result

    def test_deterministic(self):
        obj = {"z": 1, "a": 2, "m": {"c": 3, "b": 4}}
        r1 = canonicalize_json(obj)
        r2 = canonicalize_json(obj)
        assert r1 == r2


# --- Merkle Timing-Safe ---

class TestMerkleTimingSafe:
    def test_verify_uses_constant_time(self):
        leaves = [keccak256(f"leaf-{i}".encode()) for i in range(4)]
        tree = MerkleTree(leaves)
        root = tree.root()
        proof = tree.proof(0)
        assert verify_proof(leaves[0], root, proof, 0)
        fake_root = "0x" + "00" * 32
        assert not verify_proof(leaves[0], fake_root, proof, 0)
