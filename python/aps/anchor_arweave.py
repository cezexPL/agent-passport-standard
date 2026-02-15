"""Arweave anchor provider using raw HTTP calls."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .anchor import AnchorMetadata, AnchorProvider, AnchorReceipt, AnchorVerification, ProviderInfo


@dataclass
class ArweaveConfig:
    gateway_url: str = "https://arweave.net"


class ArweaveAnchor(AnchorProvider):
    def __init__(self, cfg: ArweaveConfig | None = None, *, opener: urllib.request.OpenerDirector | None = None):
        self.cfg = cfg or ArweaveConfig()
        self._opener = opener or urllib.request.build_opener()

    def commit(self, hash_bytes: bytes, meta: AnchorMetadata) -> AnchorReceipt:
        hash_hex = "0x" + hash_bytes.hex()
        tx = {
            "data": hash_hex,
            "tags": [
                {"name": "App-Name", "value": "AgentPassportStandard"},
                {"name": "APS-Hash", "value": hash_hex},
                {"name": "APS-Type", "value": meta.artifact_type},
                {"name": "Content-Type", "value": "text/plain"},
            ],
        }
        body = json.dumps(tx).encode()
        req = urllib.request.Request(
            self.cfg.gateway_url + "/tx", data=body, headers={"Content-Type": "application/json"}
        )
        resp = self._opener.open(req)
        data = json.loads(resp.read())
        tx_id = data.get("id", "")

        return AnchorReceipt(
            tx_hash=tx_id,
            block=0,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            provider="arweave",
        )

    def verify(self, hash_bytes: bytes) -> AnchorVerification:
        hash_hex = "0x" + hash_bytes.hex()
        query = {
            "query": """query($hash: String!) {
                transactions(tags: [{name: "APS-Hash", values: [$hash]}], first: 1) {
                    edges { node { id block { height timestamp } } }
                }
            }""",
            "variables": {"hash": hash_hex},
        }
        body = json.dumps(query).encode()
        req = urllib.request.Request(
            self.cfg.gateway_url + "/graphql", data=body, headers={"Content-Type": "application/json"}
        )
        resp = self._opener.open(req)
        data = json.loads(resp.read())

        edges = data.get("data", {}).get("transactions", {}).get("edges", [])
        if not edges:
            return AnchorVerification(exists=False)

        node = edges[0]["node"]
        block_info = node.get("block") or {}
        return AnchorVerification(
            exists=True,
            tx_hash=node.get("id", ""),
            block=block_info.get("height", 0),
            timestamp=datetime.fromtimestamp(block_info.get("timestamp", 0), tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ) if block_info.get("timestamp") else "",
        )

    def info(self) -> ProviderInfo:
        return ProviderInfo(name="arweave", chain_id="arweave-mainnet", type="arweave")
