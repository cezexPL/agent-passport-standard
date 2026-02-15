#!/usr/bin/env python3
"""Compute canonical JSON + keccak256 of a JSON file."""
import json, sys
from Crypto.Hash import keccak

def canonicalize(obj):
    """RFC 8785-like canonical JSON: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def keccak256(data: bytes) -> str:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return "0x" + h.hexdigest()

with open(sys.argv[1]) as f:
    obj = json.load(f)

canonical = canonicalize(obj)
print(keccak256(canonical.encode('utf-8')))
