"""Anchoring provider interface and NoOp implementation."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class AnchorReceipt:
    tx_hash: str
    block: int
    timestamp: str
    provider: str


@dataclass
class AnchorVerification:
    exists: bool
    tx_hash: str = ""
    block: int = 0
    timestamp: str = ""


@dataclass
class ProviderInfo:
    name: str
    chain_id: str
    type: str


@dataclass
class AnchorMetadata:
    artifact_type: str
    description: str = ""


class AnchorProvider(ABC):
    @abstractmethod
    def commit(self, hash_bytes: bytes, meta: AnchorMetadata) -> AnchorReceipt: ...

    @abstractmethod
    def verify(self, hash_bytes: bytes) -> AnchorVerification: ...

    @abstractmethod
    def info(self) -> ProviderInfo: ...


class NoopAnchor(AnchorProvider):
    def commit(self, hash_bytes: bytes, meta: AnchorMetadata) -> AnchorReceipt:
        return AnchorReceipt(
            tx_hash="0x" + hash_bytes.hex(),
            block=1,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            provider="noop",
        )

    def verify(self, hash_bytes: bytes) -> AnchorVerification:
        return AnchorVerification(
            exists=True,
            tx_hash="0x" + hash_bytes.hex(),
            block=1,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def info(self) -> ProviderInfo:
        return ProviderInfo(name="noop", chain_id="0", type="noop")
