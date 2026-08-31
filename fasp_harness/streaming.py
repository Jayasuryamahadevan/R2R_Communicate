"""FASP live-stream packet management.

Control envelopes remain reliable and signed. Stream frames use bounded,
sequence-numbered packets with explicit delivery mode, credit window, checksum,
deadline, and retention policy. The same framing carries JSON, telemetry,
images, audio chunks, point clouds, or arbitrary bytes.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections.abc import Iterator
from typing import Any

from .crypto.envelope import b64, unb64
from .protocol.errors import FaspError
from .storage.streams_repo import StreamsRepo

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
    ConnectionRegistry: a subscription is a property of a live session
    (push is a latency optimization on top of `pull`, which stays the
    durable, resumable reliability backstop -- FASP_MESSAGING_STREAMING.md's
    "reliable" delivery mode already has its own window/ack/retransmit
    story that a dropped push notification never bypasses), so losing it
    across a restart costs a subscriber nothing but re-sending one
    `stream.subscribe` the next time it reconnects.
    """

    def __init__(self, repo: StreamsRepo) -> None:
        self.repo = repo
        self._lock = threading.Lock()
        self._subscribers: dict[str, set[str]] = {}

    def subscribe(self, peer_id: str, stream_id: str) -> dict[str, Any]:
        stream = self.repo.get(stream_id)
        if not stream or stream["state"] != "open":
            raise FaspError("stream.not_open", "Stream is not available.")
        if peer_id == stream["owner"]:
            raise FaspError("auth.not_authorized", "A stream owner cannot subscribe to its own remote feed.")
        with self._lock:
            self._subscribers.setdefault(stream_id, set()).add(peer_id)
        return {"type": "stream.subscribed", "stream_id": stream_id, "last_sequence": stream["last_sequence"]}

    def unsubscribe(self, peer_id: str, stream_id: str) -> dict[str, Any]:
        with self._lock:
            live = self._subscribers.get(stream_id)
            if live is not None:
                live.discard(peer_id)
                if not live:
                    del self._subscribers[stream_id]
        return {"type": "stream.unsubscribed", "stream_id": stream_id}

    def subscribers_of(self, stream_id: str) -> set[str]:
        with self._lock:
            return set(self._subscribers.get(stream_id, ()))

    def open(self, owner: str, config: dict[str, Any]) -> dict[str, Any]:
        stream_id = config.get("stream_id") or str(uuid.uuid4())
        mode = config.get("delivery", "reliable")
        max_payload = int(config.get("max_payload_bytes", MAX_PACKET_BYTES))
        window = int(config.get("window", 32))
        retention = int(config.get("retention_packets", 32))
        if mode not in {"reliable", "latest"}:
            raise FaspError("schema.invalid", "delivery must be reliable or latest.")
        if not isinstance(config.get("content_type"), str) or not config["content_type"]:
            raise FaspError("schema.invalid", "Stream requires a content_type.")
        if not 1 <= max_payload <= MAX_PACKET_BYTES or not 1 <= window <= MAX_WINDOW or not 0 <= retention <= MAX_RETENTION_PACKETS:
            raise FaspError("resource.exhausted", "Stream packet, window, or retention limit is invalid.")
        existing = self.repo.get(stream_id)
        if existing is not None and existing["state"] == "open":
            return existing
        return self.repo.open(stream_id, owner, mode, config["content_type"], max_payload, window, retention)

    def packet(self, owner: str, packet: dict[str, Any]) -> dict[str, Any]:
        stream = self.repo.get(packet.get("stream_id"))
        if not stream or stream["state"] != "open" or stream["owner"] != owner:
            raise FaspError("stream.not_open", "Stream is not open for this sender.")
        sequence = packet.get("sequence")
        if not isinstance(sequence, int) or sequence < 0 or packet.get("epoch") != 0:
            raise FaspError("stream.invalid_sequence", "Packet sequence or epoch is invalid.")
        if packet.get("content_type") != stream["content_type"]:
            raise FaspError("stream.content_type_mismatch", "Packet content type differs from stream contract.")
        data = unb64(packet.get("payload", ""))
        if len(data) > stream["max_payload_bytes"] or digest(data) != packet.get("checksum"):
            raise FaspError("stream.checksum_mismatch", "Packet is oversized or its checksum is invalid.")
        if stream["delivery"] == "reliable" and sequence >= stream["next_expected"] + stream["window"]:
            raise FaspError("stream.backpressure", "Sender exceeded receiver credit window.")
        duplicate = sequence < stream["next_expected"]
        if not duplicate:
            if stream["delivery"] == "reliable" and sequence != stream["next_expected"]:
                raise FaspError("stream.out_of_order", "Reliable stream requires the next sequence; retransmit missing packet.")
            next_expected = sequence + 1
            last_sequence = max(stream["last_sequence"], sequence)
            self.repo.advance(stream["stream_id"], next_expected, last_sequence, packet if stream["retention_packets"] else None, stream["retention_packets"])
            stream["next_expected"], stream["last_sequence"] = next_expected, last_sequence
        return {"type": "stream.ack", "stream_id": stream["stream_id"], "epoch": 0, "ack_sequence": stream["next_expected"] - 1, "credit": stream["window"], "duplicate": duplicate}

    def pull(self, requester: str, stream_id: str, after_sequence: int) -> dict[str, Any]:
        stream = self.repo.get(stream_id)
        if not stream or stream["state"] != "open":
            raise FaspError("stream.not_open", "Stream is not available.")
        if requester == stream["owner"]:
            raise FaspError("auth.not_authorized", "A stream owner cannot subscribe to its own remote feed.")
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
