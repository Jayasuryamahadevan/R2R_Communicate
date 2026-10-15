"""Default-deny policy for accepting and forwarding data streams.

Capabilities answer which operation a peer may request. A stream rule adds
the data contract: who may publish it, which fields and purpose are allowed,
how quickly and how long it may run, how much may be retained, and whether it
may be forwarded to another named peer.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from ..protocol.errors import FaspError
from ..timestamps import now, parse_stamp


def _strings(value: Any, field: str, *, nonempty: bool = True) -> frozenset[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise FaspError("schema.invalid", f"Stream sharing rule {field} must be a { 'non-empty ' if nonempty else ''}list of strings.")
    if any(not isinstance(item, str) or not item.strip() for item in value) or len(set(value)) != len(value):
        raise FaspError("schema.invalid", f"Stream sharing rule {field} must contain unique, non-empty strings.")
    return frozenset(value)


def _positive_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise FaspError("schema.invalid", f"Stream sharing rule {field} must be a finite positive number.")
    return float(value)


def _positive_integer(value: Any, field: str, *, zero: bool = False) -> int:
    lower = 0 if zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < lower:
        qualifier = "non-negative" if zero else "positive"
        raise FaspError("schema.invalid", f"Stream sharing rule {field} must be a {qualifier} integer.")
    return value


@dataclass(frozen=True)
class StreamShareRule:
    capability: str
    peer_ids: frozenset[str]
    purposes: frozenset[str]
    fields: frozenset[str]
    content_types: frozenset[str]
    delivery_modes: frozenset[str]
    max_rate_hz: float
    max_duration_s: float
    max_payload_bytes: int
    max_window: int
    max_retention_packets: int
    forward_to: frozenset[str]
    require_grant: bool = True
    storage_modes: frozenset[str] = frozenset({"disk"})

    @classmethod
    def from_mapping(cls, item: Any) -> StreamShareRule:
        if not isinstance(item, dict):
            raise FaspError("schema.invalid", "Each stream sharing rule must be an object.")
        allowed = {
            "capability", "peer_ids", "purposes", "fields", "content_types",
            "delivery_modes", "max_rate_hz", "max_duration_s", "max_payload_bytes",
            "max_window", "max_retention_packets", "forward_to", "require_grant", "storage_modes",
        }
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise FaspError("schema.invalid", f"Unknown stream sharing rule keys: {unknown}.")
        capability = item.get("capability")
        if not isinstance(capability, str) or not capability or "*" in capability:
            raise FaspError("schema.invalid", "Stream sharing rule capability must be an exact capability name.")
        peer_ids = _strings(item.get("peer_ids"), "peer_ids")
        if "*" in peer_ids:
            raise FaspError("schema.invalid", "Stream sharing peer_ids must name exact paired peers.")
        delivery_modes = _strings(item.get("delivery_modes"), "delivery_modes")
        if not delivery_modes <= {"reliable", "latest"}:
            raise FaspError("schema.invalid", "Stream sharing delivery_modes may contain only 'reliable' and 'latest'.")
        max_rate_hz = _positive_number(item.get("max_rate_hz"), "max_rate_hz")
        if max_rate_hz > 10_000:
            raise FaspError("schema.invalid", "Stream sharing max_rate_hz cannot exceed 10000.")
        require_grant = item.get("require_grant", True)
        if not isinstance(require_grant, bool):
            raise FaspError("schema.invalid", "Stream sharing rule require_grant must be a boolean.")
        storage_modes = _strings(item.get("storage_modes", ["disk"]), "storage_modes")
        if not storage_modes <= {"disk", "memory"}:
            raise FaspError("schema.invalid", "Stream storage_modes may contain only disk and memory.")
        return cls(
            capability=capability,
            peer_ids=peer_ids,
            purposes=_strings(item.get("purposes"), "purposes"),
            fields=_strings(item.get("fields"), "fields"),
            content_types=_strings(item.get("content_types"), "content_types"),
            delivery_modes=delivery_modes,
            max_rate_hz=max_rate_hz,
            max_duration_s=_positive_number(item.get("max_duration_s"), "max_duration_s"),
            max_payload_bytes=_positive_integer(item.get("max_payload_bytes"), "max_payload_bytes"),
            max_window=_positive_integer(item.get("max_window"), "max_window"),
            max_retention_packets=_positive_integer(item.get("max_retention_packets"), "max_retention_packets", zero=True),
            forward_to=_strings(item.get("forward_to", []), "forward_to", nonempty=False),
            require_grant=require_grant,
            storage_modes=storage_modes,
        )


class StreamSharingPolicy:
    """Exact, local allowlist; an empty policy rejects every stream."""

    def __init__(self, rules: list[StreamShareRule] | None = None) -> None:
        self.rules = tuple(rules or ())
        identities = [(rule.capability, peer_id) for rule in self.rules for peer_id in rule.peer_ids]
        if len(identities) != len(set(identities)):
            raise FaspError("schema.invalid", "Only one stream sharing rule may match a capability and peer.")

    @classmethod
    def from_config(cls, value: Any) -> StreamSharingPolicy:
        if value is None:
            return cls()
        if not isinstance(value, list):
            raise FaspError("schema.invalid", "stream_sharing must be a list of explicit rules.")
        return cls([StreamShareRule.from_mapping(item) for item in value])

    def authorize_open(self, peer_id: str, local_id: str, payload: dict[str, Any]) -> tuple[StreamShareRule, dict[str, Any]]:
        capability = payload.get("capability")
        rule = next((candidate for candidate in self.rules if candidate.capability == capability and peer_id in candidate.peer_ids), None)
        if rule is None:
            raise FaspError("auth.not_authorized", "No local stream sharing rule permits this peer and capability.")

        purpose = payload.get("purpose")
        if not isinstance(purpose, str) or purpose not in rule.purposes:
            raise FaspError("auth.not_authorized", "Stream purpose is missing or not allowed by local policy.")
        fields = _strings(payload.get("fields"), "fields")
        if "*" in fields or not fields <= rule.fields:
            raise FaspError("auth.not_authorized", "Stream requests fields outside the local sharing allowlist.")
        content_type = payload.get("content_type")
        if not isinstance(content_type, str) or content_type not in rule.content_types:
            raise FaspError("auth.not_authorized", "Stream content type is not allowed by local policy.")

        delivery = payload.get("delivery")
        if not isinstance(delivery, str) or delivery not in rule.delivery_modes:
            raise FaspError("auth.not_authorized", "Stream delivery mode is not allowed by local policy.")
        rate = _positive_number(payload.get("max_rate_hz"), "max_rate_hz")
        duration = _positive_number(payload.get("duration_s"), "duration_s")
        max_payload = _positive_integer(payload.get("max_payload_bytes"), "max_payload_bytes")
        window = _positive_integer(payload.get("window"), "window")
        retention = _positive_integer(payload.get("retention_packets"), "retention_packets", zero=True)
        storage = payload.get("storage", "disk")
        if not isinstance(storage, str) or storage not in rule.storage_modes:
            raise FaspError("auth.not_authorized", "Stream storage mode is not allowed by local policy.")
        if storage == "memory" and (delivery != "latest" or retention != 0):
            raise FaspError("schema.invalid", "Memory streams require latest delivery and zero packet retention.")
        if rate > rule.max_rate_hz or duration > rule.max_duration_s or max_payload > rule.max_payload_bytes or window > rule.max_window or retention > rule.max_retention_packets:
            raise FaspError("auth.not_authorized", "Stream limits exceed the local sharing rule.")

        expires_at = payload.get("expires_at")
        if not isinstance(expires_at, str):
            raise FaspError("schema.invalid", "Stream requires an absolute expires_at lease deadline.")
        try:
            deadline = parse_stamp(expires_at)
        except (TypeError, ValueError) as exc:
            raise FaspError("schema.invalid", "Stream expires_at must be a valid UTC timestamp.") from exc
        current = now()
        if deadline <= current:
            raise FaspError("lease.expired", "Stream lease has already expired.")
        if deadline > current + timedelta(seconds=duration + 1):
            raise FaspError("schema.invalid", "Stream expires_at exceeds its declared duration.")

        forward_to = _strings(payload.get("forward_to", []), "forward_to", nonempty=False)
        stream_id = payload.get("stream_id")
        if stream_id is not None and (not isinstance(stream_id, str) or not stream_id):
            raise FaspError("schema.invalid", "stream_id must be a non-empty string when supplied.")
        if payload.get("recipient") != local_id:
            raise FaspError("auth.not_authorized", "Stream recipient does not match this node.")
        if peer_id in forward_to or local_id in forward_to or not forward_to <= rule.forward_to:
            raise FaspError("auth.not_authorized", "Stream forwarding recipients are not allowed by local policy.")

        contract = {
            "stream_id": stream_id,
            "capability": capability,
            "purpose": purpose,
            "fields": sorted(fields),
            "content_type": content_type,
            "recipient": local_id,
            "delivery": delivery,
            "max_rate_hz": rate,
            "duration_s": duration,
            "expires_at": expires_at,
            "max_payload_bytes": max_payload,
            "window": window,
            "retention_packets": retention,
            "forward_to": sorted(forward_to),
        }
        if "storage" in payload:
            contract["storage"] = storage
        return rule, contract
