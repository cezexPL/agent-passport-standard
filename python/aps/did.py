"""DID resolution for the Agent Passport Standard."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DIDDocument:
    id: str = ""
    verification_method: list[dict[str, Any]] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def resolve_did_key(did: str) -> DIDDocument:
    """Resolve a did:key (Ed25519 only, z6Mk prefix)."""
    if not did.startswith("did:key:z6Mk"):
        raise ValueError(f"unsupported did:key format: {did}")

    # Extract multibase-encoded key (z = base58btc)
    import base58
    multibase_value = did.split(":", 2)[2]
    # Remove 'z' prefix (base58btc indicator)
    raw_bytes = base58.b58decode(multibase_value[1:])
    # First two bytes are multicodec prefix for Ed25519 pub key (0xed, 0x01)
    if len(raw_bytes) < 34 or raw_bytes[0] != 0xED or raw_bytes[1] != 0x01:
        raise ValueError("invalid Ed25519 multicodec prefix")
    pub_key_bytes = raw_bytes[2:]

    vm = {
        "id": did + "#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": did,
        "publicKeyMultibase": multibase_value,
        "publicKeyBytes": pub_key_bytes.hex(),
    }

    return DIDDocument(
        id=did,
        verification_method=[vm],
        authentication=[did + "#key-1"],
    )


def resolve_did_web(did: str) -> DIDDocument:
    """Resolve a did:web by fetching the did.json document."""
    if not did.startswith("did:web:"):
        raise ValueError(f"not a did:web: {did}")

    # did:web:example.com -> https://example.com/.well-known/did.json
    # did:web:example.com:path:to -> https://example.com/path/to/did.json
    parts = did.split(":")[2:]
    domain = parts[0].replace("%3A", ":")
    path_parts = parts[1:] if len(parts) > 1 else []

    if path_parts:
        url = f"https://{domain}/{'/'.join(path_parts)}/did.json"
    else:
        url = f"https://{domain}/.well-known/did.json"

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = json.loads(resp.read())

    return DIDDocument(
        id=raw.get("id", did),
        verification_method=raw.get("verificationMethod", []),
        authentication=raw.get("authentication", []),
        raw=raw,
    )


def resolve(did: str) -> DIDDocument:
    """Auto-dispatch DID resolution by method."""
    if did.startswith("did:key:"):
        return resolve_did_key(did)
    elif did.startswith("did:web:"):
        return resolve_did_web(did)
    else:
        raise ValueError(f"unsupported DID method: {did}")


def extract_public_key(doc: DIDDocument) -> bytes:
    """Extract the first Ed25519 public key bytes from a DID document."""
    for vm in doc.verification_method:
        # From did:key resolution
        if "publicKeyBytes" in vm:
            return bytes.fromhex(vm["publicKeyBytes"])
        # From did:web / standard format
        if "publicKeyMultibase" in vm:
            import base58
            raw = base58.b58decode(vm["publicKeyMultibase"][1:])
            if len(raw) >= 34 and raw[0] == 0xED and raw[1] == 0x01:
                return raw[2:]
            return raw
        if "publicKeyBase58" in vm:
            import base58
            return base58.b58decode(vm["publicKeyBase58"])
    raise ValueError("no Ed25519 public key found in DID document")
