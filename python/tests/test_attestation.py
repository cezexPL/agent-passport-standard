"""Tests for attestation exchange."""
from datetime import datetime, timezone, timedelta

from aps.attestation import Attestation, create_attestation, verify_attestation, AttestationRegistry
from aps.crypto import generate_key_pair


def test_create_and_verify():
    pub, priv = generate_key_pair()
    att = create_attestation("did:key:z6MkIssuer", "did:key:z6MkSubject", "SkillVerification", {"skill": "python"}, priv)
    assert att.issuer == "did:key:z6MkIssuer"
    assert att.subject_id == "did:key:z6MkSubject"
    assert verify_attestation(att, pub) is True


def test_reject_tampered():
    pub, priv = generate_key_pair()
    att = create_attestation("did:key:z6MkIssuer", "did:key:z6MkSubject", "SkillVerification", {"skill": "python"}, priv)
    att.claims["skill"] = "hacking"
    assert verify_attestation(att, pub) is False


def test_reject_expired():
    pub, priv = generate_key_pair()
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    att = create_attestation("did:key:z6MkIssuer", "did:key:z6MkSubject", "SkillVerification", {"skill": "python"}, priv, expires_at=expired)
    assert verify_attestation(att, pub) is False


def test_reject_wrong_key():
    _, priv = generate_key_pair()
    other_pub, _ = generate_key_pair()
    att = create_attestation("did:key:z6MkIssuer", "did:key:z6MkSubject", "SkillVerification", {"skill": "python"}, priv)
    assert verify_attestation(att, other_pub) is False


def test_registry():
    pub, priv = generate_key_pair()
    registry = AttestationRegistry()
    registry.register_issuer("did:key:z6MkIssuer", pub)

    assert registry.is_trusted("did:key:z6MkIssuer") is True
    assert registry.is_trusted("did:key:z6MkUnknown") is False

    att = create_attestation("did:key:z6MkIssuer", "did:key:z6MkSubject", "SkillVerification", {"skill": "python"}, priv)
    assert registry.verify_from_registry(att) is True


def test_registry_untrusted():
    _, priv = generate_key_pair()
    registry = AttestationRegistry()

    att = create_attestation("did:key:z6MkUntrusted", "did:key:z6MkSubject", "Test", {}, priv)
    try:
        registry.verify_from_registry(att)
        assert False, "should have raised"
    except ValueError:
        pass


def test_roundtrip_dict():
    _, priv = generate_key_pair()
    att = create_attestation("did:key:z6MkIssuer", "did:key:z6MkSubject", "Test", {"a": 1}, priv)
    d = att.to_dict()
    att2 = Attestation.from_dict(d)
    assert att2.issuer == att.issuer
    assert att2.proof_value == att.proof_value
