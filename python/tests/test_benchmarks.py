"""Performance benchmarks for APS Python SDK.

Run with: python3 -m pytest tests/test_benchmarks.py -v
Uses simple timeit since pytest-benchmark may not be installed.
"""
import time
import statistics

from aps.crypto import (
    canonicalize_json,
    keccak256,
    keccak256_bytes,
    snapshot_hash,
    ed25519_sign,
    ed25519_verify,
    generate_key_pair,
    MerkleTree,
)
from aps.passport import AgentPassport, PassportConfig, Skill, Soul, Policies, Lineage


def _bench(fn, iterations=1000):
    """Run fn iterations times, return (mean_us, min_us, max_us)."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1_000_000)  # µs
    return statistics.mean(times), min(times), max(times)


def _make_config():
    pub, priv = generate_key_pair()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return PassportConfig(
        id="did:key:z6MkBenchTest1234567890abcdefghijklmnop",
        public_key=pub_hex,
        owner_did="did:key:z6MkBenchOwner1234567890abcdefghijklmno",
        skills=[Skill(
            name="python-backend", version="1.0.0",
            description="Python backend development",
            capabilities=["code_write"],
            hash="0x0000000000000000000000000000000000000000000000000000000000000000",
        )],
        soul=Soul(
            personality="Efficient", work_style="Systematic",
            constraints=["no-external-calls"],
            hash="0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        policies=Policies(
            policy_set_hash="0x0000000000000000000000000000000000000000000000000000000000000000",
            summary=["read-only"],
        ),
        lineage=Lineage(kind="original", parents=[], generation=0),
    ), pub, priv


def test_benchmark_keccak256():
    data = b"The quick brown fox jumps over the lazy dog"
    mean, mn, mx = _bench(lambda: keccak256(data), 5000)
    print(f"\nkeccak256: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 1000  # should be well under 1ms


def test_benchmark_canonicalize():
    obj = {"z": "last", "a": 42, "m": ["x", "y"], "nested": {"b": 2, "a": 1}}
    mean, mn, mx = _bench(lambda: canonicalize_json(obj), 3000)
    print(f"\ncanonicalize_json: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 5000


def test_benchmark_passport_create():
    cfg, _, _ = _make_config()
    mean, mn, mx = _bench(lambda: AgentPassport.new(cfg), 1000)
    print(f"\npassport create: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 50000


def test_benchmark_sign_verify():
    cfg, pub, priv = _make_config()
    p = AgentPassport.new(cfg)

    def sign_verify():
        p.sign(priv)
        p.verify(pub)

    mean, mn, mx = _bench(sign_verify, 500)
    print(f"\nsign+verify: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 100000


def test_benchmark_merkle_1000():
    leaves = [keccak256(f"leaf-{i}".encode()) for i in range(1000)]

    def build():
        mt = MerkleTree(leaves)
        _ = mt.root()

    mean, mn, mx = _bench(build, 100)
    print(f"\nmerkle 1000 leaves: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 1_000_000


def test_benchmark_ed25519_sign():
    _, priv = generate_key_pair()
    data = b"benchmark signing payload"
    mean, mn, mx = _bench(lambda: ed25519_sign(priv, data), 2000)
    print(f"\ned25519_sign: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 10000


def test_benchmark_ed25519_verify():
    pub, priv = generate_key_pair()
    data = b"benchmark verify payload"
    sig = ed25519_sign(priv, data)
    mean, mn, mx = _bench(lambda: ed25519_verify(pub, data, sig), 2000)
    print(f"\ned25519_verify: mean={mean:.1f}µs min={mn:.1f}µs max={mx:.1f}µs")
    assert mean < 10000
