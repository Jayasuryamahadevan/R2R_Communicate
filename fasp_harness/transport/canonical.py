"""One ingress boundary for every FASP bearer.

A packet is a signed FASP envelope. A stream is a leased, ordered sequence of
signed ``stream.packet`` envelopes. Bearers decode their framing here, then
hand the same object to ``FaspHarness.accept``. Artifact references remain an
optional storage path for large one-time values.
"""

from __future__ import annotations

import json
import math
from typing import TYPE_CHECKING, Any

from ..protocol.contracts import MAX_RECORD_BYTES, PROTOCOL, validate_json
from ..protocol.errors import FaspError

if TYPE_CHECKING:
    from ..core import FaspHarness

MAX_ENVELOPE_BYTES = MAX_RECORD_BYTES
RECEIPT_WRAPPED_KINDS = frozenset({"intent.propose", "task.cancel", "artifact.fetch"})


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite number {value}")


def _safe_int(value: str) -> int:
    result = int(value)
    if abs(result) > 2**53 - 1:
        raise ValueError("integer exceeds the canonical JSON safe range")
    return result


def _safe_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def decode_object(raw: bytes, *, limit: int = MAX_ENVELOPE_BYTES) -> dict[str, Any]:
    """Decode one bounded, unambiguous UTF-8 JSON object from any bearer."""
    if not raw:
        raise FaspError("schema.invalid", "Packet body is empty.")
    if len(raw) > limit:
        raise FaspError("resource.too_large", "Packet exceeds its size limit.")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite, parse_int=_safe_int, parse_float=_safe_float,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise FaspError("schema.invalid", "Packet must contain valid UTF-8 JSON without duplicate keys or non-finite numbers.") from exc
    if not isinstance(value, dict):
        raise FaspError("schema.invalid", "Packet must contain a JSON object.")
    validate_json(value)
    return value


def accept_envelope(harness: FaspHarness, envelope: dict[str, Any], *, expected_kind: str | None = None, wrap_receipt: bool = True) -> dict[str, Any]:
    """Preserve the existing signed dispatch and receipt semantics."""
    duplicate, response = harness.accept(envelope, expected_kind)
    if response is None:
        raise FaspError("transport.response_unavailable", "Envelope has no recorded response; retry after recovery.")
    if response.get("type") == "protocol.error":
        error = response["error"]
        raise FaspError(error["code"], error["detail"])
    if wrap_receipt and envelope.get("kind") in RECEIPT_WRAPPED_KINDS:
        return {"fasp": PROTOCOL, "type": "receipt.delivered", "duplicate": duplicate, "message_id": envelope.get("message_id"), "response": response}
    return response
