"""Tests for APS schema validation."""
import copy
import pytest
from jsonschema import ValidationError
from aps.validate import validate_passport, validate_dna

HEX64 = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
DID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"

VALID_PASSPORT = {
    "@context": "https://agentpassport.org/v0.1",
    "spec_version": "0.1.0",
    "type": "AgentPassport",
    "id": DID,
    "keys": {"signing": {"algorithm": "Ed25519", "public_key": "z6MkpTHR"}},
    "genesis_owner": {"id": DID, "bound_at": "2025-01-01T00:00:00Z", "immutable": True},
    "current_owner": {"id": DID},
    "snapshot": {
        "version": 1,
        "hash": HEX64,
        "prev_hash": None,
        "created_at": "2025-01-01T00:00:00Z",
        "skills": {
            "entries": [{"name": "go", "version": "1.0", "description": "Go", "capabilities": ["code"], "hash": HEX64}],
            "frozen": False,
        },
        "soul": {"personality": "f", "work_style": "t", "constraints": [], "hash": HEX64, "frozen": False},
        "policies": {"policy_set_hash": HEX64, "summary": ["can_bid"]},
    },
    "lineage": {"kind": "single", "parents": [], "generation": 0},
    "proof": {
        "type": "Ed25519Signature2020",
        "created": "2025-01-01T00:00:00Z",
        "verification_method": f"{DID}#keys-1",
        "proof_purpose": "assertionMethod",
        "proof_value": "zSIG",
    },
}

VALID_DNA = {
    "@context": "https://agentpassport.org/v0.2/dna",
    "type": "AgentDNA",
    "agent_id": DID,
    "version": 1,
    "skills": [],
    "soul": {"personality": "f", "work_style": "t", "constraints": []},
    "policies": {"policy_set_hash": HEX64, "summary": ["x"]},
    "dna_hash": HEX64,
    "frozen": False,
}


def test_valid_passport():
    validate_passport(VALID_PASSPORT)


def test_missing_context():
    d = copy.deepcopy(VALID_PASSPORT)
    del d["@context"]
    with pytest.raises(ValidationError):
        validate_passport(d)


def test_missing_id():
    d = copy.deepcopy(VALID_PASSPORT)
    del d["id"]
    with pytest.raises(ValidationError):
        validate_passport(d)


def test_wrong_type_spec_version():
    d = copy.deepcopy(VALID_PASSPORT)
    d["spec_version"] = 123
    with pytest.raises(ValidationError):
        validate_passport(d)


def test_extra_fields_passport():
    # additionalProperties: false in passport schema
    d = copy.deepcopy(VALID_PASSPORT)
    d["extra"] = "hello"
    with pytest.raises(ValidationError):
        validate_passport(d)


def test_skills_entries_wrong_type():
    d = copy.deepcopy(VALID_PASSPORT)
    d["snapshot"]["skills"]["entries"] = "not-array"
    with pytest.raises(ValidationError):
        validate_passport(d)


def test_valid_dna():
    validate_dna(VALID_DNA)


def test_dna_missing_hash():
    d = copy.deepcopy(VALID_DNA)
    del d["dna_hash"]
    with pytest.raises(ValidationError):
        validate_dna(d)
