"""Tests for DID resolution."""
from aps.did import resolve_did_key, extract_public_key
from aps.crypto import generate_key_pair
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base58


def test_resolve_did_key():
    pub, _ = generate_key_pair()
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Build did:key from Ed25519 public key
    multicodec = b'\xed\x01' + pub_bytes
    multibase = 'z' + base58.b58encode(multicodec).decode()
    did = f"did:key:{multibase}"

    doc = resolve_did_key(did)
    assert doc.id == did
    assert len(doc.verification_method) == 1

    extracted = extract_public_key(doc)
    assert extracted == pub_bytes


def test_resolve_did_key_invalid():
    import pytest
    with pytest.raises(ValueError):
        resolve_did_key("did:key:invalid")
