"""Tests for ReputationSummary."""
from aps.reputation import ReputationSummary
from aps.crypto import generate_key_pair


def test_create_reputation():
    r = ReputationSummary(
        agent_did="did:key:z6MkTest",
        generated_at="2025-01-01T00:00:00Z",
        total_jobs=10,
        successful_jobs=9,
        failed_jobs=1,
        average_score=0.95,
        trust_tier=2,
        attestation_count=3,
    )
    assert r.total_jobs == 10


def test_sign_verify():
    pub, priv = generate_key_pair()
    r = ReputationSummary(
        agent_did="did:key:z6MkTest",
        generated_at="2025-01-01T00:00:00Z",
        total_jobs=5,
        successful_jobs=5,
    )
    r.sign(priv)
    assert r.proof is not None
    assert r.verify(pub)


def test_roundtrip_json():
    pub, priv = generate_key_pair()
    r = ReputationSummary(
        agent_did="did:key:z6MkTest",
        generated_at="2025-01-01T00:00:00Z",
        total_jobs=5,
    )
    r.sign(priv)
    data = r.to_json()
    r2 = ReputationSummary.from_json(data)
    assert r2.agent_did == "did:key:z6MkTest"
    assert r2.verify(pub)
