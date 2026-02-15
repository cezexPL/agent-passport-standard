"""Tests for WorkReceipt."""
from aps.receipt import WorkReceipt, ReceiptConfig
from aps.crypto import generate_key_pair, MerkleTree


def _make_receipt() -> WorkReceipt:
    return WorkReceipt.new(ReceiptConfig(
        receipt_id="550e8400-e29b-41d4-a716-446655440000",
        job_id="550e8400-e29b-41d4-a716-446655440001",
        agent_did="did:key:z6MkAgent",
        client_did="did:key:z6MkClient",
        agent_snapshot={"version": 1, "hash": "0x" + "aa" * 32},
    ))


def test_full_lifecycle():
    r = _make_receipt()
    r.add_event({"type": "claim", "timestamp": "2026-02-14T01:00:00Z",
                 "payload_hash": "0x" + "01" * 32, "signature": "sig1"})
    r.add_event({"type": "submit", "timestamp": "2026-02-14T01:30:00Z",
                 "payload_hash": "0x" + "02" * 32, "signature": "sig2"})
    r.add_event({"type": "verify", "timestamp": "2026-02-14T01:35:00Z",
                 "payload_hash": "0x" + "03" * 32, "signature": "sig3",
                 "result": {"status": "accepted", "score": 87}})
    r.add_event({"type": "payout", "timestamp": "2026-02-14T01:40:00Z",
                 "payload_hash": "0x" + "04" * 32, "signature": "sig4",
                 "amount": {"value": 500, "unit": "points"}})
    assert len(r.events) == 4
    assert r.events[0]["type"] == "claim"
    assert r.events[3]["type"] == "payout"


def test_sign_verify():
    pub, priv = generate_key_pair()
    r = _make_receipt()
    r.add_event({"type": "claim", "timestamp": "2026-02-14T01:00:00Z",
                 "payload_hash": "0x01", "signature": "s"})
    r.sign(priv)
    assert r.proof is not None
    assert r.receipt_hash.startswith("0x")
    assert r.verify(pub)


def test_batch_proof():
    r1 = _make_receipt()
    r1.add_event({"type": "claim", "timestamp": "2026-02-14T01:00:00Z",
                  "payload_hash": "0x01", "signature": "s"})
    r2 = _make_receipt()
    r2.receipt_id = "other-id"
    r2.add_event({"type": "claim", "timestamp": "2026-02-14T02:00:00Z",
                  "payload_hash": "0x02", "signature": "s2"})

    h1 = r1.hash()
    h2 = r2.hash()
    tree = MerkleTree([h1, h2])
    root = tree.root()
    proof = tree.proof(0)

    r1.batch_proof = {
        "batch_root": root,
        "leaf_index": 0,
        "proof": proof,
    }
    assert r1.batch_proof["batch_root"] == root


def test_from_json_roundtrip():
    r = _make_receipt()
    r.add_event({"type": "claim", "timestamp": "2026-02-14T01:00:00Z",
                 "payload_hash": "0x01", "signature": "s"})
    data = r.to_json()
    r2 = WorkReceipt.from_json(data, validate=False)
    assert r2.receipt_id == r.receipt_id
    assert len(r2.events) == 1
