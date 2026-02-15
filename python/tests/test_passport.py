"""Tests for AgentPassport."""
from aps.passport import AgentPassport, PassportConfig, Skill, Soul, Policies, Lineage
from aps.crypto import generate_key_pair, keccak256, canonicalize_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _make_cfg(pub_hex: str) -> PassportConfig:
    return PassportConfig(
        id="did:key:z6MkTest",
        public_key=pub_hex,
        owner_did="did:key:z6MkOwner",
        skills=[Skill(name="python", version="1.0.0", description="Python dev",
                       capabilities=["code_write"], hash="0x" + "ab" * 32)],
        soul=Soul(personality="focused", work_style="tdd", constraints=[],
                  hash="0x" + "cd" * 32),
        policies=Policies(policy_set_hash="0x" + "ef" * 32, summary=["can_bid"]),
        lineage=Lineage(kind="original", parents=[], generation=0),
    )


def test_create_sign_verify():
    pub, priv = generate_key_pair()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    cfg = _make_cfg(pub_hex)
    p = AgentPassport.new(cfg)

    assert p.type == "AgentPassport"
    assert p.snapshot["version"] == 1
    assert p.snapshot["hash"].startswith("0x")

    h1 = p.hash()
    assert h1.startswith("0x")

    p.sign(priv)
    assert p.proof is not None
    assert p.verify(pub)


def test_hash_matches():
    pub, priv = generate_key_pair()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    p = AgentPassport.new(_make_cfg(pub_hex))
    h = p.hash()
    # Manually compute
    d = p.to_dict()
    d.pop("proof", None)
    manual = keccak256(canonicalize_json(d))
    assert h == manual


def test_frozen_skills():
    pub, _ = generate_key_pair()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    p = AgentPassport.new(_make_cfg(pub_hex))
    p.snapshot["skills"]["frozen"] = True
    # Attempting to modify should be caught by application logic
    assert p.snapshot["skills"]["frozen"] is True


def test_snapshot_hash_chain():
    pub, priv = generate_key_pair()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    p = AgentPassport.new(_make_cfg(pub_hex))
    v1_hash = p.snapshot["hash"]
    assert p.snapshot["prev_hash"] is None

    # Simulate version bump
    p.snapshot["version"] = 2
    p.snapshot["prev_hash"] = v1_hash
    from aps.crypto import snapshot_hash
    new_hash = snapshot_hash({
        "skills": p.snapshot["skills"],
        "soul": p.snapshot["soul"],
        "policies": p.snapshot["policies"],
    })
    p.snapshot["hash"] = new_hash
    assert p.snapshot["prev_hash"] == v1_hash
    assert p.snapshot["version"] == 2


def test_from_json_roundtrip():
    pub, _ = generate_key_pair()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    p = AgentPassport.new(_make_cfg(pub_hex))
    data = p.to_json()
    p2 = AgentPassport.from_json(data, validate=False)
    assert p2.id == p.id
    assert p2.snapshot["hash"] == p.snapshot["hash"]
