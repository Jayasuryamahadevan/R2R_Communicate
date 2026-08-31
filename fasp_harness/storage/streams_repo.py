"""Live-stream control state and bounded packet retention (`streams` /
`stream_packets` tables). See fasp_harness/streaming.py for the framing
(packetize/Reassembler) and authorization logic built on top of this.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .db import Database


class StreamsRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self, stream_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM streams WHERE stream_id = ?", (stream_id,))
        return _row_to_stream(row) if row is not None else None

    def open(self, stream_id: str, owner: str, delivery: str, content_type: str, max_payload_bytes: int, window: int, retention_packets: int) -> dict[str, Any]:
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO streams (stream_id, owner, state, delivery, content_type, max_payload_bytes, window, retention_packets, next_expected, last_sequence, opened_at_monotonic_ns) "
                "VALUES (?, ?, 'open', ?, ?, ?, ?, ?, 0, -1, ?)",
                (stream_id, owner, delivery, content_type, max_payload_bytes, window, retention_packets, time.monotonic_ns()),
            )
        stream = self.get(stream_id)
        assert stream is not None
        return stream

    def advance(self, stream_id: str, next_expected: int, last_sequence: int, retained_packet: dict[str, Any] | None, retention_packets: int) -> None:
        """Advance a stream's sequence state and, if retention is enabled,
        append + prune the retained-packet window in the same transaction."""
        with self.db.write() as conn:
            conn.execute("UPDATE streams SET next_expected = ?, last_sequence = ? WHERE stream_id = ?", (next_expected, last_sequence, stream_id))
            if retained_packet is not None and retention_packets:
                conn.execute(
                    "INSERT INTO stream_packets (stream_id, sequence, packet_json) VALUES (?, ?, ?)",
                    (stream_id, retained_packet["sequence"], json.dumps(retained_packet)),
                )
                # Bound retained packets even against a malicious sender:
                # keep only the newest `retention_packets` rows for this stream.
                conn.execute(
                    "DELETE FROM stream_packets WHERE stream_id = ? AND sequence NOT IN "
                    "(SELECT sequence FROM stream_packets WHERE stream_id = ? ORDER BY sequence DESC LIMIT ?)",
                    (stream_id, stream_id, retention_packets),
                )

    def packets_after(self, stream_id: str, after_sequence: int) -> list[dict[str, Any]]:
        rows = self.db.read("SELECT packet_json FROM stream_packets WHERE stream_id = ? AND sequence > ? ORDER BY sequence", (stream_id, after_sequence))
        return [json.loads(row["packet_json"]) for row in rows]

    def close(self, stream_id: str, reason: str) -> None:
        with self.db.write() as conn:
            conn.execute(
                "UPDATE streams SET state = 'closed', closed_reason = ?, closed_at_monotonic_ns = ? WHERE stream_id = ?",
                (reason, time.monotonic_ns(), stream_id),
            )


def _row_to_stream(row: Any) -> dict[str, Any]:
    return {
        "stream_id": row["stream_id"],
        "owner": row["owner"],
        "state": row["state"],
        "delivery": row["delivery"],
        "content_type": row["content_type"],
        "max_payload_bytes": row["max_payload_bytes"],
        "window": row["window"],
        "retention_packets": row["retention_packets"],
        "next_expected": row["next_expected"],
        "last_sequence": row["last_sequence"],
    }
