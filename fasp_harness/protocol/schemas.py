"""Portable JSON Schema and OpenAPI contracts for the baseline wire profile.

Structural schemas do not replace signature, time, identity, replay or policy
checks. Export with ``python -m fasp_harness.protocol.schemas``.
"""

from __future__ import annotations

import json
from typing import Any

from .contracts import MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_RECORD_BYTES, PROTOCOL, SYSTEM_ID_PATTERN, WIRE_PROFILE


def definitions() -> dict[str, Any]:
    name = {"type": "string", "minLength": 1, "maxLength": 128}
    identity = {"type": "string", "pattern": SYSTEM_ID_PATTERN}
    timestamp = {"type": "string", "format": "date-time", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"}
    signature = {
        "type": "object", "required": ["alg", "kid", "value"],
        "properties": {"alg": {"const": "Ed25519"}, "kid": name, "value": {"type": "string", "pattern": r"^[A-Za-z0-9_-]{86}$"}},
    }
    features = {"type": "array", "maxItems": 32, "uniqueItems": True, "items": name}
    return {
        "Signature": signature,
        "Envelope": {
            "type": "object",
            "required": ["fasp", "kind", "message_id", "from", "to", "issued_at", "expires_at", "nonce", "payload", "signature"],
            "properties": {
                "fasp": {"const": PROTOCOL}, "kind": name, "message_id": name,
                "conversation_id": {"type": ["string", "null"], "minLength": 1, "maxLength": 128},
                "causation_id": {"type": ["string", "null"], "minLength": 1, "maxLength": 128},
                "from": identity, "to": identity, "issued_at": timestamp, "expires_at": timestamp,
                "nonce": name, "payload": {"type": "object"}, "signature": signature, "required_features": features,
            },
            "additionalProperties": True,
            "description": "Signature covers every field except signature. Unknown required_features MUST fail closed. Domain payload validation and authorization follow authentication.",
        },
        "IdCard": {
            "type": "object", "required": ["fasp", "type", "system_id", "public_key", "endpoints", "expires_at", "signature"],
            "properties": {
                "fasp": {"const": PROTOCOL}, "type": {"const": "id_card"}, "system_id": identity,
                "key_id": name, "public_key": {"type": "string", "pattern": r"^[A-Za-z0-9_-]{43}$"},
                "display_name": {"type": "string", "minLength": 1, "maxLength": 256},
                "endpoints": {"type": "object", "additionalProperties": {"type": ["string", "null"]}},
                "issued_at": timestamp, "expires_at": timestamp, "signature": signature, "required_features": features,
                "protocol_support": {"type": "object"},
            },
            "additionalProperties": True,
        },
    }


def wire_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:fasp:schema:wire:v1", "title": WIRE_PROFILE,
        "oneOf": [{"$ref": "#/$defs/Envelope"}, {"$ref": "#/$defs/IdCard"}],
        "$defs": definitions(),
        "x-fasp-limits": {"max_record_bytes": MAX_RECORD_BYTES, "max_json_depth": MAX_JSON_DEPTH, "max_json_nodes": MAX_JSON_NODES},
    }


if __name__ == "__main__":
    print(json.dumps(wire_schema(), indent=2, ensure_ascii=False))
