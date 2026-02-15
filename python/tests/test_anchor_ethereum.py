"""Tests for Ethereum anchor provider."""
import json
import http.server
import threading

from aps.anchor import AnchorMetadata
from aps.anchor_ethereum import EthereumAnchor, EthereumConfig


def _make_mock_server(handler_class):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class EthCommitHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        method = body.get("method")

        if method == "eth_sendTransaction":
            resp = {"jsonrpc": "2.0", "result": "0xabc123", "id": 1}
        elif method == "eth_getTransactionReceipt":
            resp = {"jsonrpc": "2.0", "result": {"blockNumber": "0xa"}, "id": 1}
        else:
            resp = {"jsonrpc": "2.0", "result": None, "id": 1}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


class EthVerifyHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, anchored=True, **kwargs):
        self._anchored = anchored
        super().__init__(*args, **kwargs)

    def do_POST(self):
        val = "0x0000000000000000000000000000000000000000000000000000000000000001"
        resp = {"jsonrpc": "2.0", "result": val, "id": 1}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


class EthVerifyFalseHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        val = "0x0000000000000000000000000000000000000000000000000000000000000000"
        resp = {"jsonrpc": "2.0", "result": val, "id": 1}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


def test_ethereum_commit():
    server = _make_mock_server(EthCommitHandler)
    try:
        cfg = EthereumConfig(
            rpc_url=f"http://127.0.0.1:{server.server_address[1]}",
            contract_address="0x1234567890123456789012345678901234567890",
            from_address="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        provider = EthereumAnchor(cfg)
        receipt = provider.commit(b"\x01" * 32, AnchorMetadata(artifact_type="passport"))
        assert receipt.tx_hash == "0xabc123"
        assert receipt.block == 10
        assert receipt.provider == "ethereum"
    finally:
        server.shutdown()


def test_ethereum_verify_true():
    server = _make_mock_server(EthVerifyHandler)
    try:
        cfg = EthereumConfig(
            rpc_url=f"http://127.0.0.1:{server.server_address[1]}",
            contract_address="0x1234567890123456789012345678901234567890",
        )
        provider = EthereumAnchor(cfg)
        v = provider.verify(b"\x01" * 32)
        assert v.exists is True
    finally:
        server.shutdown()


def test_ethereum_verify_false():
    server = _make_mock_server(EthVerifyFalseHandler)
    try:
        cfg = EthereumConfig(
            rpc_url=f"http://127.0.0.1:{server.server_address[1]}",
            contract_address="0x1234567890123456789012345678901234567890",
        )
        provider = EthereumAnchor(cfg)
        v = provider.verify(b"\x01" * 32)
        assert v.exists is False
    finally:
        server.shutdown()


def test_ethereum_info():
    cfg = EthereumConfig(rpc_url="http://localhost", contract_address="0x0", chain_id="8453")
    provider = EthereumAnchor(cfg)
    info = provider.info()
    assert info.name == "ethereum"
    assert info.chain_id == "8453"
    assert info.type == "ethereum"
