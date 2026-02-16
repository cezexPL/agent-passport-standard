"""Tests for §20 Execution Attestation."""
from aps.execution import ExecutionAttestation


class TestExecutionAttestation:
    def test_round_trip(self):
        a = ExecutionAttestation(
            envelope_hash="sha256:abc",
            measurement="m1",
            platform="sgx",
            nonce="nonce1",
            report_signature="sig1",
            trust_level=2,
        )
        d = a.to_dict()
        assert d["envelopeHash"] == "sha256:abc"
        assert d["trustLevel"] == 2
        a2 = ExecutionAttestation.from_dict(d)
        assert a2 == a

    def test_camel_keys(self):
        d = ExecutionAttestation().to_dict()
        for k in d:
            assert "_" not in k

    def test_validate_ok(self):
        a = ExecutionAttestation(envelope_hash="h", trust_level=3)
        assert a.validate() == []

    def test_validate_trust_level_range(self):
        for bad in [-1, 4, 100]:
            a = ExecutionAttestation(envelope_hash="h", trust_level=bad)
            assert len(a.validate()) >= 1

    def test_validate_missing_hash(self):
        a = ExecutionAttestation(trust_level=0)
        assert any("envelope_hash" in e for e in a.validate())
