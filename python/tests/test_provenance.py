"""Tests for §18 Provenance."""
from aps.provenance import Provenance


class TestProvenance:
    def test_round_trip(self):
        p = Provenance(
            model_digest="sha256:aaa",
            toolchain_digest="sha256:bbb",
            prompt_template_hash="sha256:ccc",
            policy_hash="sha256:ddd",
            runtime_version="1.0.0",
            parent_receipt_ids=["r1", "r2"],
            pipeline_id="pipe-1",
            step_index=3,
            watermark="wm-123",
        )
        d = p.to_dict()
        assert d["modelDigest"] == "sha256:aaa"
        assert d["stepIndex"] == 3
        p2 = Provenance.from_dict(d)
        assert p2 == p

    def test_camel_case_keys(self):
        d = Provenance().to_dict()
        for key in d:
            assert "_" not in key

    def test_validate_negative_step(self):
        assert len(Provenance(step_index=-1).validate()) == 1

    def test_validate_ok(self):
        assert Provenance().validate() == []
