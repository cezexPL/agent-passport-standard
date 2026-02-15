"""Ethereum (EVM) anchor provider using raw JSON-RPC calls."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .anchor import AnchorMetadata, AnchorProvider, AnchorReceipt, AnchorVerification, ProviderInfo

# anchor(bytes32) selector
ANCHOR_SELECTOR = "0xc2b12a73"
# isAnchored(bytes32) selector
IS_ANCHORED_SELECTOR = "0xa85f7489"


@dataclass
class EthereumConfig:
    rpc_url: str
    contract_address: str
    chain_id: str = "1"
    from_address: str = ""
    private_key: str = ""


class EthereumAnchor(AnchorProvider):
    def __init__(self, cfg: EthereumConfig, *, opener: urllib.request.OpenerDirector | None = None):
        self.cfg = cfg
        self._opener = opener or urllib.request.build_opener()

    def _rpc_call(self, method: str, params: list) -> object:
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
        req = urllib.request.Request(self.cfg.rpc_url, data=body, headers={"Content-Type": "application/json"})
        resp = self._opener.open(req)
        data = json.loads(resp.read())
        if data.get("error"):
            raise RuntimeError(f"RPC error: {data['error']}")
        return data.get("result")

    def commit(self, hash_bytes: bytes, meta: AnchorMetadata) -> AnchorReceipt:
        data = ANCHOR_SELECTOR + hash_bytes.hex().ljust(64, "0")[:64]
        tx = {"from": self.cfg.from_address, "to": self.cfg.contract_address, "data": data}
        tx_hash = self._rpc_call("eth_sendTransaction", [tx])

        block = 0
        try:
            receipt = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
            if receipt and receipt.get("blockNumber"):
                block = int(receipt["blockNumber"], 16)
        except Exception:
            pass

        return AnchorReceipt(
            tx_hash=tx_hash,
            block=block,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            provider="ethereum",
        )

    def verify(self, hash_bytes: bytes) -> AnchorVerification:
        data = IS_ANCHORED_SELECTOR + hash_bytes.hex().ljust(64, "0")[:64]
        call = {"to": self.cfg.contract_address, "data": data}
        result = self._rpc_call("eth_call", [call, "latest"])

        is_anchored = False
        if isinstance(result, str):
            clean = result.replace("0x", "")
            if len(clean) >= 64:
                is_anchored = clean[63] == "1"

        if not is_anchored:
            return AnchorVerification(exists=False)

        return AnchorVerification(
            exists=True,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def info(self) -> ProviderInfo:
        return ProviderInfo(name="ethereum", chain_id=self.cfg.chain_id, type="ethereum")
