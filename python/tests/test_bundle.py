"""Tests for AgentPassportBundle."""
import json
from aps.bundle import AgentPassportBundle
from aps.crypto import generate_key_pair


def _make_bundle():
    bundle = AgentPassportBundle(
        passport={"id": "did:key:z6MkTest", "type": "AgentPassport", "keys": {}},
        work_receipts=[{"receipt_id": "r1", "type": "WorkReceipt"}],
        attestations=[{"issuer": "did:key:z6MkIssuer"}],
        reputation_summary={"agent_did": "did:key:z6MkTest", "total_jobs": 5},
        anchor_proofs=[],
    )
    return bundle


def test_create_bundle():
    b = _make_bundle()
    assert b.passport["id"] == "did:key:z6MkTest"
    assert len(b.work_receipts) == 1


def test_sign_verify():
    pub, priv = generate_key_pair()
    b = _make_bundle()
    b.sign(priv)
    assert b.proof is not None
    assert b.verify(pub)


def test_verify_fails_wrong_key():
    _, priv = generate_key_pair()
    pub2, _ = generate_key_pair()
    b = _make_bundle()
    b.sign(priv)
    assert not b.verify(pub2)


def test_roundtrip_json():
    pub, priv = generate_key_pair()
    b = _make_bundle()
    b.sign(priv)
    data = b.to_json()
    b2 = AgentPassportBundle.from_json(data)
    assert b2.passport["id"] == "did:key:z6MkTest"
    assert b2.proof is not None
    assert b2.verify(pub)
