"""Tests for §19 Key Rotation & Identity Chain."""
from aps.rotation import KeyRotation, IdentityChain


class TestKeyRotation:
    def test_round_trip(self):
        r = KeyRotation(old_did="did:key:old", new_did="did:key:new", reason="compromised", rotated_at="2025-01-01T00:00:00Z", proof="sig123")
        d = r.to_dict()
        assert d["oldDid"] == "did:key:old"
        assert d["newDid"] == "did:key:new"
        r2 = KeyRotation.from_dict(d)
        assert r2 == r

    def test_validate_ok(self):
        r = KeyRotation(old_did="a", new_did="b")
        assert r.validate() == []

    def test_validate_missing(self):
        r = KeyRotation(old_did="", new_did="")
        assert len(r.validate()) == 3

    def test_validate_same(self):
        r = KeyRotation(old_did="x", new_did="x")
        errors = r.validate()
        assert any("must differ" in e for e in errors)


class TestIdentityChain:
    def _chain(self):
        return IdentityChain(rotations=[
            KeyRotation(old_did="did:1", new_did="did:2", rotated_at="t1"),
            KeyRotation(old_did="did:2", new_did="did:3", rotated_at="t2"),
            KeyRotation(old_did="did:3", new_did="did:4", rotated_at="t3"),
        ])

    def test_round_trip(self):
        c = self._chain()
        c2 = IdentityChain.from_dict(c.to_dict())
        assert c2.to_dict() == c.to_dict()

    def test_current_did(self):
        assert self._chain().current_did() == "did:4"

    def test_original_did(self):
        assert self._chain().original_did() == "did:1"

    def test_chain_length(self):
        assert self._chain().chain_length() == 3

    def test_find_rotation(self):
        r = self._chain().find_rotation("did:2")
        assert r is not None
        assert r.new_did == "did:3"

    def test_find_rotation_missing(self):
        assert self._chain().find_rotation("did:99") is None

    def test_trace(self):
        assert self._chain().trace("did:1") == ["did:2", "did:3", "did:4"]
        assert self._chain().trace("did:3") == ["did:4"]
        assert self._chain().trace("did:4") == []

    def test_empty_chain(self):
        c = IdentityChain()
        assert c.current_did() is None
        assert c.original_did() is None
        assert c.chain_length() == 0
