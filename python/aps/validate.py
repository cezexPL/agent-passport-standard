"""JSON Schema validation for APS documents."""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError  # noqa: F401

_SPEC_DIR = Path(__file__).resolve().parent.parent.parent / "spec"

def _load_schema(name: str) -> dict:
    with open(_SPEC_DIR / name) as f:
        return json.load(f)

def _validate(data: dict[str, Any], schema_name: str) -> None:
    schema = _load_schema(schema_name)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        raise ValidationError(errors[0].message, path=errors[0].path, schema_path=errors[0].schema_path)

def validate_passport(data: dict[str, Any]) -> None:
    """Validate a passport dict against agent-passport.schema.json. Raises ValidationError."""
    _validate(data, "agent-passport.schema.json")

def validate_receipt(data: dict[str, Any]) -> None:
    """Validate a receipt dict against work-receipt.schema.json. Raises ValidationError."""
    _validate(data, "work-receipt.schema.json")

def validate_envelope(data: dict[str, Any]) -> None:
    """Validate an envelope dict against security-envelope.schema.json. Raises ValidationError."""
    _validate(data, "security-envelope.schema.json")

def validate_dna(data: dict[str, Any]) -> None:
    """Validate a DNA dict against dna.schema.json. Raises ValidationError."""
    _validate(data, "dna.schema.json")
