"""Transport-independent wire validation. No storage, adapter, or HTTP imports.

Validate structure before signature verification or database access. Optional
extension fields remain signed; an unknown *required* feature fails closed.
"""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

from ..crypto.canonical import canonicalize
from ..timestamps import parse_stamp
from .errors import FaspError
from .volatile import MAX_VOLATILE_LIFETIME_S, VOLATILE_FEATURE, VOLATILE_KINDS

PROTOCOL = "fasp/1.0"
WIRE_PROFILE = "fasp-json-ed25519-v1"
MAX_RECORD_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 8192
MAX_CLOCK_SKEW_SECONDS = 60
SUPPORTED_FEATURES = frozenset({"fasp.required-features.v1", VOLATILE_FEATURE})
SYSTEM_ID_PATTERN = r"^fasp:system:[A-Za-z0-9_-]{43}$"


def invalid(detail: str) -> None:
    raise FaspError("schema.invalid", detail)


def text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        invalid(f"{name} must be a nonempty string of at most {maximum} characters.")
    return value


def validate_json(value: Any) -> None:
    """Bound nesting and reject values JCS cannot represent, including surrogates."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise FaspError("resource.too_large", "JSON structure exceeds the profile depth or node limit.")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    invalid("JSON object keys must be strings.")
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError as error:
                raise FaspError("schema.invalid", "JSON strings must contain valid Unicode scalar values.") from error
        elif item is None or isinstance(item, bool):
            continue
        elif isinstance(item, int):
            if abs(item) > 2**53 - 1:
                invalid("JSON integers must be in the safe IEEE 754 integer range.")
        elif isinstance(item, float):
            if not math.isfinite(item):
                invalid("JSON numbers must be finite.")
            if item.is_integer() and abs(item) > 2**53 - 1:
                invalid("Integer-valued JSON numbers must be in the safe IEEE 754 integer range.")
        else:
            invalid("Only JSON values are accepted.")


def record(value: Any, required: set[str]) -> bytes:
    if not isinstance(value, dict) or not required.issubset(value):
        invalid("Record misses required FASP fields.")
    validate_json(value)
    # Serialize the signed content once. Its canonical bytes are also the
    # verifier's input; computing the full record and then unsigned content
    # duplicated the most expensive pure-Python work on every request.
    content = canonicalize({key: item for key, item in value.items() if key != "signature"})
    signature_bytes = canonicalize(value["signature"])
    if len(content) + len(b',"signature":') + len(signature_bytes) > MAX_RECORD_BYTES:
        raise FaspError("resource.too_large", "Record exceeds 64 KiB.")
    if not isinstance(value["fasp"], str):
        invalid("fasp must be a protocol version string.")
    if value["fasp"] != PROTOCOL:
        raise FaspError("protocol.unsupported_version", "Protocol version is not supported.")
    return content


def timestamp(value: Any, name: str) -> datetime:
    # RFC 3339, with an explicit offset. datetime.fromisoformat alone accepts
    # dates, naive timestamps, week dates, and other non-wire representations.
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        invalid(f"{name} must be an RFC 3339 timestamp with a timezone.")
    try:
        return parse_stamp(value)
    except (ValueError, OverflowError) as error:
        raise FaspError("schema.invalid", "Timestamp contains an invalid date or offset.") from error


def lifetime(value: dict[str, Any], *, issued_required: bool = True) -> tuple[datetime | None, datetime]:
    expires = timestamp(value["expires_at"], "expires_at")
    issued = timestamp(value["issued_at"], "issued_at") if issued_required or "issued_at" in value else None
    if issued is not None and expires <= issued:
        invalid("expires_at must be later than issued_at.")
    return issued, expires


def system_id(value: Any, name: str) -> None:
    if not isinstance(value, str) or re.fullmatch(SYSTEM_ID_PATTERN, value) is None:
        invalid(f"{name} must be a SHA-256 base64url FASP system identity.")


def required_features(value: dict[str, Any]) -> None:
    features = value.get("required_features", [])
    if not isinstance(features, list) or len(features) > 32 or any(not isinstance(item, str) or not item or len(item) > 128 for item in features):
        invalid("required_features must be an array of at most 32 feature names.")
    if len(set(features)) != len(features):
        invalid("required_features must not contain duplicates.")
    if not set(features) <= SUPPORTED_FEATURES:
        raise FaspError("protocol.unsupported_feature", "A required protocol feature is not implemented.")


def check_peer_features(card: dict[str, Any], features: Any) -> None:
    """Sender-side guard: legacy peers cannot be trusted to reject extensions."""
    required_features({"required_features": features})
    if not features:
        return
    support = card.get("protocol_support", {})
    advertised = support.get("features", []) if isinstance(support, dict) else []
    if (
        not isinstance(advertised, list) or any(not isinstance(item, str) for item in advertised)
        or "fasp.required-features.v1" not in advertised or not set(features) <= set(advertised)
    ):
        raise FaspError("protocol.unsupported_feature", "Verified peer does not advertise the required extension semantics.")


def envelope_shape(value: Any) -> tuple[datetime, datetime, bytes]:
    content = record(value, {"fasp", "kind", "message_id", "from", "to", "issued_at", "expires_at", "nonce", "payload", "signature"})
    for name in ("kind", "message_id", "nonce"):
        text(value[name], name, 128)
    for name in ("from", "to"):
        system_id(value[name], name)
    for name in ("conversation_id", "causation_id"):
        if value.get(name) is not None:
            text(value[name], name, 128)
    if not isinstance(value["payload"], dict):
        invalid("Envelope payload must be an object.")
    required_features(value)
    issued, expires = lifetime(value)
    delivery = value.get("delivery", "durable")
    if not isinstance(delivery, str) or delivery not in {"durable", "volatile"}:
        invalid("Envelope delivery must be durable or volatile.")
    if delivery == "volatile":
        if value["kind"] not in VOLATILE_KINDS or VOLATILE_FEATURE not in value.get("required_features", []):
            raise FaspError("protocol.unsupported_delivery", "Volatile delivery requires its feature and an observation-only request kind.")
        text(value.get("receiver_instance"), "receiver_instance", 128)
        if (expires - issued).total_seconds() > MAX_VOLATILE_LIFETIME_S:
            invalid("Volatile message lifetime cannot exceed five seconds.")
    return issued, expires, content


def id_card_shape(value: Any) -> tuple[datetime | None, datetime, bytes]:
    content = record(value, {"fasp", "type", "system_id", "public_key", "endpoints", "expires_at", "signature"})
    if value["type"] != "id_card":
        invalid("Record must be an id_card.")
    system_id(value["system_id"], "system_id")
    text(value["public_key"], "public_key", 43)
    endpoints = value["endpoints"]
    # A client-only participant has null endpoints (the TypeScript bridge).
    if not isinstance(endpoints, dict) or any(item is not None and not isinstance(item, str) for item in endpoints.values()):
        invalid("ID card endpoints must map names to URLs or null.")
    if "display_name" in value:
        text(value["display_name"], "display_name")
    if "instance_id" in value:
        text(value["instance_id"], "instance_id", 128)
    if "key_id" in value:
        text(value["key_id"], "key_id", 128)
        if not isinstance(value["signature"], dict) or value["signature"].get("kid") != value["key_id"]:
            raise FaspError("auth.invalid_signature", "Signature key identifier does not match the signed ID card.")
    required_features(value)
    issued, expires = lifetime(value, issued_required=False)
    return issued, expires, content


def scopes(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 128:
        invalid("Capability scopes must be an array of at most 128 names.")
    for item in value:
        text(item, "capability scope")
        if re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?", item) is None:
            invalid("Capability scopes must contain dot-separated names without wildcards.")


def number(value: Any, name: str, minimum: float, maximum: float, *, integer: bool = False) -> None:
    expected = int if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, expected) or not math.isfinite(value) or not minimum <= value <= maximum:
        invalid(f"{name} is outside its permitted numeric range.")


def payload_shape(kind: str, payload: dict[str, Any]) -> None:
    """Validate fields used as DB keys or converted by dispatch handlers.

    Domain-specific stream, fleet and spatial validators still own their
    full semantic contracts. This gate prevents type coercion at ingress.
    """
    names: tuple[str, ...] = ()
    if kind == "intent.propose":
        names = ("intent_id", "idempotency_key", "capability", "risk", "objective")
        if "constraints" in payload and not isinstance(payload["constraints"], dict):
            invalid("Intent constraints must be an object.")
    elif kind in {"task.cancel", "task.status"}:
        names = ("idempotency_key",)
    elif kind == "artifact.fetch":
        names = ("artifact_id",)
    elif kind == "receipt.processed":
        names = ("message_id",)
    elif kind.startswith("stream."):
        names = ("stream_id", "capability")
    elif kind.startswith("reservation."):
        names = ("reservation_id",)
    elif kind in {"mission.status", "mission.cancel"}:
        names = ("mission_id",)
    for name in names:
        if name in payload and payload[name] is not None:
            text(payload[name], name, MAX_RECORD_BYTES if name == "objective" else 256)
    if kind == "inbox.pull" and "cursor" in payload:
        number(payload["cursor"], "cursor", 0, 253402300799)
    if kind == "stream.pull" and "after_sequence" in payload:
        number(payload["after_sequence"], "after_sequence", -1, 2**53 - 1, integer=True)
    if kind == "reservation.request" and "lease_ms" in payload:
        number(payload["lease_ms"], "lease_ms", 1000, 120000, integer=True)


def operator_payload(path: str, payload: dict[str, Any]) -> None:
    """Local administrative HTTP shapes; values are never silently coerced."""
    fields = {
        "/pair/confirm": ("peer_id", "pair_code"),
        "/pair/revoke": ("peer_id",),
        "/grants/issue": ("subject_peer",),
        "/grants/revoke": ("grant_id",),
    }.get(path, ())
    for name in fields:
        text(payload.get(name), name)
    for name in ("allowed_capability_prefixes", "capability_prefixes"):
        if name in payload and payload[name] is not None:
            scopes(payload[name])
    if path == "/grants/issue":
        scopes(payload.get("capability_prefixes"))
        number(payload.get("duration_seconds", 3600), "duration_seconds", 1, 90 * 86400, integer=True)
        if payload.get("purpose") is not None:
            text(payload["purpose"], "purpose", 1024)
        if payload.get("constraints") is not None and not isinstance(payload["constraints"], dict):
            invalid("Grant constraints must be an object.")
    if path == "/pair/revoke":
        for name in ("reason", "revocation_ref"):
            if payload.get(name) is not None:
                text(payload[name], name, 1024)


def wire_support(kinds: list[str]) -> dict[str, Any]:
    """Signed discovery metadata, describing implemented wire behavior only."""
    return {
        "profile": WIRE_PROFILE,
        "versions": [PROTOCOL],
        "identity_encoding": "sha256-base64url-no-padding",
        "canonicalization": "RFC8785",
        "signature": "Ed25519",
        "features": sorted(SUPPORTED_FEATURES),
        "delivery_modes": ["durable", "volatile"],
        "volatile_kinds": sorted(VOLATILE_KINDS),
        "max_volatile_lifetime_s": MAX_VOLATILE_LIFETIME_S,
        "accepted_kinds": sorted(kinds),
        "limits": {"max_record_bytes": MAX_RECORD_BYTES, "max_json_depth": MAX_JSON_DEPTH, "max_json_nodes": MAX_JSON_NODES},
    }
