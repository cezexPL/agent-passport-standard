"""Tests for §21 Sybil Resistance & Reputation Score."""
import time
import math
from unittest.mock import patch
from aps.sybil import ReputationScore, RatingEntry, compute_decay


class TestComputeDecay:
    def test_recent(self):
        # Very recent timestamp → decay ≈ 1
        assert compute_decay(time.time(), 0.001) == pytest.approx(1.0, abs=0.01)

    def test_old(self):
        # 1000 seconds ago with λ=0.001 → e^(-1) ≈ 0.368
        assert compute_decay(time.time() - 1000, 0.001) == pytest.approx(math.exp(-1), abs=0.01)

    def test_future_clamped(self):
        # Future timestamp → delta clamped to 0 → decay = 1
        assert compute_decay(time.time() + 9999, 0.001) == 1.0


class TestRatingEntry:
    def test_round_trip(self):
        r = RatingEntry(weight=1.0, rating=0.9, timestamp=1000.0)
        r2 = RatingEntry.from_dict(r.to_dict())
        assert r2 == r


class TestReputationScore:
    def test_empty(self):
        assert ReputationScore().compute() == 0.0

    def test_zero_weight(self):
        rs = ReputationScore(entries=[RatingEntry(weight=0, rating=1.0, timestamp=time.time())])
        assert rs.compute() == 0.0

    @patch("aps.sybil.time.time", return_value=1000.0)
    def test_compute_known(self, mock_time):
        # All timestamps = now → decay = 1.0
        rs = ReputationScore(entries=[
            RatingEntry(weight=2.0, rating=0.8, timestamp=1000.0),
            RatingEntry(weight=3.0, rating=0.6, timestamp=1000.0),
        ])
        # R = (2*0.8*1 + 3*0.6*1) / (2+3) = (1.6+1.8)/5 = 0.68
        assert rs.compute() == pytest.approx(0.68, abs=1e-9)

    def test_round_trip(self):
        rs = ReputationScore(
            entries=[RatingEntry(weight=1.0, rating=0.5, timestamp=500.0)],
            lambda_=0.01,
        )
        d = rs.to_dict()
        assert d["lambda"] == 0.01
        rs2 = ReputationScore.from_dict(d)
        assert rs2.lambda_ == 0.01
        assert len(rs2.entries) == 1

    def test_validate_ok(self):
        rs = ReputationScore(entries=[RatingEntry(weight=1, rating=1, timestamp=0)])
        assert rs.validate() == []

    def test_validate_negative_lambda(self):
        rs = ReputationScore(lambda_=-0.5)
        assert len(rs.validate()) >= 1

    def test_validate_negative_weight(self):
        rs = ReputationScore(entries=[RatingEntry(weight=-1, rating=1, timestamp=0)])
        assert any("weight" in e for e in rs.validate())


import pytest
