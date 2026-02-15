"""Tests for Arweave anchor provider."""
import json
import http.server
import threading

from aps.anchor import AnchorMetadata
from aps.anchor_arweave import ArweaveAnchor, ArweaveConfig


def _make_mock_server(handler_class):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class ArweaveCommitHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        resp = {"id": "arweave-tx-id-12345"}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


class ArweaveVerifyFoundHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        resp = {"data": {"transactions": {"edges": [{"node": {"id": "ar-tx-123", "block": {"height": 100, "timestamp": 1700000000}}}]}}}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


class ArweaveVerifyNotFoundHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        resp = {"data": {"transactions": {"edges": []}}}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass


def test_arweave_commit():
    server = _make_mock_server(ArweaveCommitHandler)
    try:
        cfg = ArweaveConfig(gateway_url=f"http://127.0.0.1:{server.server_address[1]}")
        provider = ArweaveAnchor(cfg)
        receipt = provider.commit(b"\x01" * 32, AnchorMetadata(artifact_type="passport"))
        assert receipt.tx_hash == "arweave-tx-id-12345"
        assert receipt.provider == "arweave"
    finally:
        server.shutdown()


def test_arweave_verify_found():
    server = _make_mock_server(ArweaveVerifyFoundHandler)
    try:
        cfg = ArweaveConfig(gateway_url=f"http://127.0.0.1:{server.server_address[1]}")
        provider = ArweaveAnchor(cfg)
        v = provider.verify(b"\x01" * 32)
        assert v.exists is True
        assert v.tx_hash == "ar-tx-123"
        assert v.block == 100
    finally:
        server.shutdown()


def test_arweave_verify_not_found():
    server = _make_mock_server(ArweaveVerifyNotFoundHandler)
    try:
        cfg = ArweaveConfig(gateway_url=f"http://127.0.0.1:{server.server_address[1]}")
        provider = ArweaveAnchor(cfg)
        v = provider.verify(b"\x01" * 32)
        assert v.exists is False
    finally:
        server.shutdown()


def test_arweave_info():
    provider = ArweaveAnchor()
    info = provider.info()
    assert info.name == "arweave"
    assert info.type == "arweave"
