"""Tests for NoopAnchor."""
from aps.anchor import NoopAnchor, AnchorMetadata


def test_noop_commit_verify():
    anchor = NoopAnchor()
    h = b"\x01" * 32
    receipt = anchor.commit(h, AnchorMetadata(artifact_type="passport"))
    assert receipt.tx_hash == "0x" + "01" * 32
    assert receipt.block == 1
    assert receipt.provider == "noop"

    v = anchor.verify(h)
    assert v.exists is True
    assert v.tx_hash == "0x" + "01" * 32


def test_noop_info():
    anchor = NoopAnchor()
    info = anchor.info()
    assert info.type == "noop"
    assert info.name == "noop"
