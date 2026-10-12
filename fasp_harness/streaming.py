"""FASP live-stream packet management.

Control envelopes remain reliable and signed. Stream frames use bounded,
sequence-numbered packets with explicit delivery mode, credit window, checksum,
deadline, and retention policy. The same framing carries JSON, telemetry,
images, audio chunks, point clouds, or arbitrary bytes.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from typing import Any

from .crypto.envelope import b64, unb64
from .protocol.errors import FaspError
from .storage.streams_repo import StreamsRepo
from .timestamps import now, parse_stamp

# Base64 plus envelope metadata must remain inside the 64 KiB signed envelope.
MAX_PACKET_BYTES = 40 * 1024
MAX_WINDOW = 512
MAX_RETENTION_PACKETS = 4096


def digest(data: bytes) -> str:
    return "sha-256:" + hashlib.sha256(data).hexdigest()


def packetize(stream_id: str, epoch: int, sequence_start: int, data: bytes, content_type: str, max_payload_bytes: int = MAX_PACKET_BYTES) -> Iterator[dict[str, Any]]:
    """Split arbitrary bytes into self-describing, integrity-checked frames."""
    if not 1 <= max_payload_bytes <= MAX_PACKET_BYTES:
        raise ValueError("max_payload_bytes must be within the FASP packet bound")
    if content_type == "application/json" and len(data) > max_payload_bytes:
        raise ValueError("application/json records must fit in one FASP packet")
    frame_id = str(uuid.uuid4())
    chunks = [data[index:index + max_payload_bytes] for index in range(0, len(data), max_payload_bytes)] or [b""]
    # Milliseconds, not time.monotonic_ns(): this field rides inside a signed
    # envelope payload, which RFC 8785 canonicalization (fasp_harness.crypto.
    # canonical) restricts to the IEEE 754 safe-integer domain (+-2**53-1).
    # Nanosecond-since-boot values cross that after ~104 days of uptime;
    # milliseconds stay safe for roughly 285,000 years.
    sent_ms = time.monotonic_ns() // 1_000_000
    for index, chunk in enumerate(chunks):
        yield {
            "stream_id": stream_id,
            "epoch": epoch,
            "sequence": sequence_start + index,
            "sent_monotonic_ms": sent_ms,
            "content_type": content_type,
            "frame_id": frame_id,
            "fragment_index": index,
            "fragment_count": len(chunks),
            "payload": b64(chunk),
            "checksum": digest(chunk),
        }


class Reassembler:
    """Bounded reassembly of a fragmented frame on a consumer."""

    def __init__(self, max_frame_bytes: int = 4 * 1024 * 1024) -> None:
        self.max_frame_bytes = max_frame_bytes
        self.frames: dict[str, dict[str, Any]] = {}

    def add(self, packet: dict[str, Any]) -> bytes | None:
        data = unb64(packet["payload"])
        if digest(data) != packet["checksum"]:
            raise FaspError("stream.checksum_mismatch", "Packet checksum did not match payload.")
        count, index = int(packet["fragment_count"]), int(packet["fragment_index"])
        if not 1 <= count <= MAX_WINDOW or not 0 <= index < count:
            raise FaspError("stream.invalid_fragment", "Packet fragment metadata is invalid.")
        state = self.frames.setdefault(packet["frame_id"], {"count": count, "parts": {}, "bytes": 0})
        if state["count"] != count:
            raise FaspError("stream.invalid_fragment", "Frame fragment count changed mid-frame.")
        if index not in state["parts"]:
            state["parts"][index] = data
            state["bytes"] += len(data)
        if state["bytes"] > self.max_frame_bytes:
            self.frames.pop(packet["frame_id"], None)
            raise FaspError("resource.exhausted", "Reassembly frame exceeds local limit.")
        if len(state["parts"]) != count:
            return None
        output = b"".join(state["parts"][part] for part in range(count))
        self.frames.pop(packet["frame_id"], None)
        return output


class StreamRegistry:
    """Durable stream control state and bounded packet retention.

    Live-push subscriptions are the one piece of state here that is
    deliberately NOT durable, same reasoning as channels.py's
    ConnectionRegistry: a subscription is a peer-level, in-memory preference
    that lasts until unsubscribe, revocation, stream expiry, or process restart.
    Push is a latency optimization on top of `pull`, which stays the durable,
    resumable reliability backstop -- a dropped push notification never bypasses
    the window/ack/retransmit story. A WebSocket reconnect within the same node
    process reuses the subscription, but every future packet is reauthorized.
    """

    def __init__(self, repo: StreamsRepo) -> None:
        self.repo = repo
        self._lock = threading.RLock()
        self._subscribers: dict[str, dict[str, dict[str, str]]] = {}

    def subscribe(self, peer_id: str, stream_id: str, grant_ref: dict[str, str]) -> dict[str, Any]:
        stream = self.repo.get(stream_id)
        self._require_active(stream)
        if peer_id == stream["owner"]:
            raise FaspError("auth.not_authorized", "A stream owner cannot subscribe to its own remote feed.")
        if peer_id not in stream["contract"].get("forward_to", []):
            raise FaspError("auth.not_authorized", "The stream owner did not authorize sharing with this subscriber.")
        with self._lock:
            self._subscribers.setdefault(stream_id, {})[peer_id] = dict(grant_ref)
        return {"type": "stream.subscribed", "stream_id": stream_id, "last_sequence": stream["last_sequence"]}

    def unsubscribe(self, peer_id: str, stream_id: str) -> dict[str, Any]:
        with self._lock:
            live = self._subscribers.get(stream_id)
            if live is not None:
                live.pop(peer_id, None)
                if not live:
                    del self._subscribers[stream_id]
        return {"type": "stream.unsubscribed", "stream_id": stream_id}

    def subscribers_of(self, stream_id: str) -> set[str]:
        with self._lock:
            return set(self._subscribers.get(stream_id, ()))

    def subscription_grants_of(self, stream_id: str) -> dict[str, dict[str, str]]:
        """Return a snapshot of each live subscriber's consent reference."""
        with self._lock:
            return {peer_id: dict(grant_ref) for peer_id, grant_ref in self._subscribers.get(stream_id, {}).items()}

    def open(self, owner: str, config: dict[str, Any]) -> dict[str, Any]:
        stream_id = config.get("stream_id") or str(uuid.uuid4())
        if not 1 <= config["max_payload_bytes"] <= MAX_PACKET_BYTES or not 1 <= config["window"] <= MAX_WINDOW or not 0 <= config["retention_packets"] <= MAX_RETENTION_PACKETS:
            raise FaspError("resource.exhausted", "Stream packet, window, or retention limit is invalid.")
        existing = self.repo.get(stream_id)
        contract = dict(config)
        contract["stream_id"] = stream_id
        if existing is not None:
            if existing["owner"] == owner and existing["state"] == "open" and existing["contract"] == contract:
                self._require_active(existing)
                return existing
            raise FaspError("stream.id_conflict", "Stream ID is already in use and cannot be reopened with a different contract.")
        return self.repo.open(stream_id, owner, contract)

    def packet(self, owner: str, packet: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            stream = self.repo.get(packet.get("stream_id"))
            self._require_active(stream)
            if stream["owner"] != owner:
                raise FaspError("stream.not_open", "Stream is not open for this sender.")
            sequence = packet.get("sequence")
            epoch = packet.get("epoch")
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence < 0
                or isinstance(epoch, bool)
                or epoch != 0
            ):
                raise FaspError("stream.invalid_sequence", "Packet sequence or epoch is invalid.")
            if packet.get("capability") != stream["contract"]["capability"]:
                raise FaspError("stream.capability_mismatch", "Packet capability differs from the accepted stream contract.")
            if packet.get("content_type") != stream["content_type"]:
                raise FaspError("stream.content_type_mismatch", "Packet content type differs from stream contract.")
            data = unb64(packet.get("payload", ""))
            if len(data) > stream["max_payload_bytes"] or digest(data) != packet.get("checksum"):
                raise FaspError("stream.checksum_mismatch", "Packet is oversized or its checksum is invalid.")
            if stream["content_type"] == "application/json":
                self._validate_json_record(packet, stream["contract"], data)
            if stream["delivery"] == "reliable" and sequence >= stream["next_expected"] + stream["window"]:
                raise FaspError("stream.backpressure", "Sender exceeded receiver credit window.")
            duplicate = sequence < stream["next_expected"]
            if not duplicate:
                if stream["delivery"] == "reliable" and sequence != stream["next_expected"]:
                    raise FaspError("stream.out_of_order", "Reliable stream requires the next sequence; retransmit missing packet.")
                received_at = now()
                last_packet_at = stream.get("last_packet_at")
                if last_packet_at is not None:
                    minimum_interval = 1.0 / stream["contract"]["max_rate_hz"]
                    elapsed = (received_at - parse_stamp(last_packet_at)).total_seconds()
                    if elapsed < minimum_interval:
                        raise FaspError("stream.rate_exceeded", "Sender exceeded the stream's accepted maximum rate.")
                next_expected = sequence + 1
                last_sequence = max(stream["last_sequence"], sequence)
                received_text = received_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
                self.repo.advance(
                    stream["stream_id"],
                    next_expected,
                    last_sequence,
                    packet if stream["retention_packets"] else None,
                    stream["retention_packets"],
                    received_text,
                )
                stream["next_expected"], stream["last_sequence"] = next_expected, last_sequence
                stream["last_packet_at"] = received_text
            return {"type": "stream.ack", "stream_id": stream["stream_id"], "epoch": 0, "ack_sequence": stream["next_expected"] - 1, "credit": stream["window"], "duplicate": duplicate}

    @staticmethod
    def _validate_json_record(packet: dict[str, Any], contract: dict[str, Any], data: bytes) -> None:
        """Enforce declared top-level JSON fields before data enters the stream."""
        if type(packet.get("fragment_count")) is not int or packet["fragment_count"] != 1 or type(packet.get("fragment_index")) is not int or packet["fragment_index"] != 0:
            raise FaspError("stream.invalid_json", "JSON records must fit in one complete packet.")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate JSON object key")
                value[key] = item
            return value

        def reject_nonfinite(value: str) -> None:
            raise ValueError(f"non-finite JSON number: {value}")

        try:
            record = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise FaspError("stream.invalid_json", "JSON packet must contain one valid UTF-8 JSON object.") from exc
        if not isinstance(record, dict):
            raise FaspError("stream.invalid_json", "JSON packet must contain one top-level object.")
        undeclared = set(record) - set(contract["fields"])
        if undeclared:
            raise FaspError("auth.not_authorized", "JSON packet contains fields outside the accepted stream contract.")

    def pull(self, requester: str, stream_id: str, after_sequence: int) -> dict[str, Any]:
        stream = self.repo.get(stream_id)
        self._require_active(stream)
        if requester == stream["owner"]:
            raise FaspError("auth.not_authorized", "A stream owner cannot subscribe to its own remote feed.")
        if requester not in stream["contract"].get("forward_to", []):
            raise FaspError("auth.not_authorized", "The stream owner did not authorize sharing with this recipient.")
        packets = self.repo.packets_after(stream_id, after_sequence)
        return {"stream_id": stream_id, "packets": packets, "last_sequence": stream["last_sequence"]}

    def close(self, owner: str, stream_id: str, reason: str) -> dict[str, Any]:
        stream = self.repo.get(stream_id)
        if not stream or stream["owner"] != owner:
            raise FaspError("stream.not_open", "Stream is not owned by this sender.")
        reason = reason[:160]
        self.repo.close(stream_id, reason)
        with self._lock:
            self._subscribers.pop(stream_id, None)
        return {"type": "stream.closed", "stream_id": stream_id, "reason": reason}

    def expire(self, stream_id: str) -> None:
        self.repo.close(stream_id, "lease expired")
        with self._lock:
            self._subscribers.pop(stream_id, None)

    def _require_active(self, stream: dict[str, Any] | None) -> None:
        if stream is None or stream["state"] != "open":
            raise FaspError("stream.not_open", "Stream is not available.")
        expires_at = stream.get("expires_at")
        if not isinstance(expires_at, str) or parse_stamp(expires_at) <= now():
            self.expire(stream["stream_id"])
            raise FaspError("lease.expired", "Stream lease has expired.")
