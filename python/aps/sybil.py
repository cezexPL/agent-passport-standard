"""§21 Sybil Resistance & Reputation Score types for the Agent Passport Standard."""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any


def compute_decay(timestamp: float, lambda_: float = 0.001) -> float:
    """Compute time-decay factor: e^(-λ * Δt) where Δt = now - timestamp (seconds)."""
    delta = time.time() - timestamp
    if delta < 0:
        delta = 0
    return math.exp(-lambda_ * delta)


@dataclass
class RatingEntry:
    weight: float
    rating: float
    timestamp: float  # unix epoch

    def to_dict(self) -> dict[str, Any]:
        return {
            "weight": self.weight,
            "rating": self.rating,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> RatingEntry:
        return cls(
            weight=raw["weight"],
            rating=raw["rating"],
            timestamp=raw["timestamp"],
        )


@dataclass
class ReputationScore:
    entries: list[RatingEntry] = field(default_factory=list)
    lambda_: float = 0.001

    def compute(self) -> float:
        """Compute R = Σ(w_i × r_i × d_i) / Σ(w_i) where d_i = decay(timestamp_i)."""
        if not self.entries:
            return 0.0
        numerator = 0.0
        denominator = 0.0
        for e in self.entries:
            d = compute_decay(e.timestamp, self.lambda_)
            numerator += e.weight * e.rating * d
            denominator += e.weight
        if denominator == 0:
            return 0.0
        return numerator / denominator

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "lambda": self.lambda_,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ReputationScore:
        return cls(
            entries=[RatingEntry.from_dict(e) for e in raw.get("entries", [])],
            lambda_=raw.get("lambda", 0.001),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.lambda_ < 0:
            errors.append("lambda must be >= 0")
        for i, e in enumerate(self.entries):
            if e.weight < 0:
                errors.append(f"entries[{i}]: weight must be >= 0")
        return errors
