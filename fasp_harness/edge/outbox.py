"""Durable store-and-forward: the difference between "offline" and "lost".

A coordinator that must talk to a WMS across a plant network, or to a
vehicle over patchy Wi-Fi in an aisle lined with steel racking, spends a
meaningful fraction of its life unable to reach the thing it needs. The
common failure is to treat that as an error: the send fails, the caller
logs it, and the instruction evaporates.

The outbox inverts it. Sending is two steps -- durably record the intent to
send, then attempt delivery -- and only the first step is on the caller's
path. A partition then costs latency, and the queue drains itself when the
link returns.

Three properties make it safe rather than merely persistent:

- **at-least-once, deduplicated at the receiver.** Retries are inherent to
  this design, so every message carries the `message_id` that FASP's
  existing replay-dedup gate keys on. A duplicate delivery returns the
  original response instead of repeating an effect.
- **per-destination ordering.** Messages to one destination are attempted
  in enqueue order, so a cancel cannot overtake the order it cancels.
  Different destinations proceed independently, so one unreachable peer
  cannot stall every other.
- **bounded.** Capped exponential backoff with jitter, a maximum attempt
  count that dead-letters instead of retrying forever, an absolute expiry
  after which a message is dropped rather than delivered uselessly late,
  and a depth cap that rejects an enqueue rather than filling the disk.
"""

from __future__ import annotations

import json
import random
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..protocol.errors import FaspError
from ..storage.db import Database
from ..timestamps import stamp

DEFAULT_MAX_ATTEMPTS = 12
DEFAULT_BASE_BACKOFF_S = 0.5
DEFAULT_MAX_BACKOFF_S = 300.0
DEFAULT_CAPACITY = 10_000


@dataclass(frozen=True)
class OutboxMessage:
    row_id: int
    message_id: str
    destination: str
    kind: str
    envelope: dict[str, Any]
    attempts: int
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"row_id": self.row_id, "message_id": self.message_id, "destination": self.destination, "kind": self.kind, "attempts": self.attempts, "created_at": self.created_at}


class Outbox:
    """A durable, ordered, bounded send queue."""

    def __init__(
        self,
        db: Database,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_backoff_s: float = DEFAULT_BASE_BACKOFF_S,
        max_backoff_s: float = DEFAULT_MAX_BACKOFF_S,
        capacity: int = DEFAULT_CAPACITY,
        jitter: Callable[[], float] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.db = db
        self.max_attempts = max_attempts
        self.base_backoff_s = base_backoff_s
        self.max_backoff_s = max_backoff_s
        self.capacity = capacity
        # Injectable so a test can make backoff deterministic; full jitter
        # (random between 0 and the computed delay) in production, because
        # synchronised retries after a partition heals are how a recovering
        # link gets knocked over a second time.
        self.jitter = jitter if jitter is not None else random.random
        # Injectable so the whole queue can run on virtual time inside the
        # network simulator (see fasp_harness/resilience/faults.py), and so
        # a backoff assertion is a fact rather than a race.
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.Lock()

    def now_ms(self) -> int:
        return int(self._clock())

    # -- enqueue --------------------------------------------------------
    def enqueue(self, destination: str, envelope: dict[str, Any], *, expires_in_s: float | None = None, not_before_s: float = 0.0) -> OutboxMessage:
        """Durably record one message. Idempotent on `message_id`."""
        message_id = envelope.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            raise FaspError("schema.invalid", "An outbox message requires the envelope's message_id.")
        now_ms = self.now_ms()
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        with self.db.write() as conn:
            existing = conn.execute("SELECT row_id, attempts, created_at FROM outbox WHERE message_id = ?", (message_id,)).fetchone()
            if existing is not None:
                return OutboxMessage(int(existing["row_id"]), message_id, destination, str(envelope.get("kind", "")), envelope, int(existing["attempts"]), existing["created_at"])
            depth = conn.execute("SELECT COUNT(*) AS n FROM outbox WHERE state IN ('pending', 'inflight')").fetchone()["n"]
            if depth >= self.capacity:
                raise FaspError("resource.exhausted", f"Outbox is at its capacity of {self.capacity} undelivered messages.")
            cursor = conn.execute(
                "INSERT INTO outbox (message_id, destination, kind, envelope_json, state, attempts, next_attempt_ms, expires_at_ms, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)",
                (
                    message_id,
                    destination,
                    str(envelope.get("kind", "")),
                    body,
                    now_ms + int(not_before_s * 1000),
                    now_ms + int(expires_in_s * 1000) if expires_in_s else None,
                    stamp(),
                    stamp(),
                ),
            )
            row_id = int(cursor.lastrowid or 0)
        return OutboxMessage(row_id, message_id, destination, str(envelope.get("kind", "")), envelope, 0, stamp())

    # -- drain ------------------------------------------------------------
    def claim_ready(self, limit: int = 32, now_ms: int | None = None) -> list[OutboxMessage]:
        """Claim the next due message per destination, marking it inflight.

        One per destination, not one per row: that is what preserves
        per-destination ordering while letting independent destinations make
        progress in parallel. A destination whose head message is backing
        off contributes nothing to this batch, and does not block others.
        """
        now_ms = now_ms if now_ms is not None else self.now_ms()
        claimed: list[OutboxMessage] = []
        with self._lock, self.db.write() as conn:
            conn.execute("UPDATE outbox SET state = 'dead', last_error = 'expired before delivery', updated_at = ? WHERE state = 'pending' AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?", (stamp(), now_ms))
            rows = conn.execute(
                "SELECT row_id, message_id, destination, kind, envelope_json, attempts, created_at FROM outbox o WHERE state = 'pending' AND next_attempt_ms <= ? "
                "AND row_id = (SELECT MIN(row_id) FROM outbox WHERE destination = o.destination AND state IN ('pending', 'inflight')) "
                "ORDER BY row_id LIMIT ?",
                (now_ms, limit),
            ).fetchall()
            for row in rows:
                conn.execute("UPDATE outbox SET state = 'inflight', updated_at = ? WHERE row_id = ?", (stamp(), int(row["row_id"])))
                claimed.append(
                    OutboxMessage(int(row["row_id"]), row["message_id"], row["destination"], row["kind"], json.loads(row["envelope_json"]), int(row["attempts"]), row["created_at"])
                )
        return claimed

    def mark_sent(self, row_id: int) -> None:
        with self.db.write() as conn:
            conn.execute("UPDATE outbox SET state = 'sent', updated_at = ?, last_error = NULL WHERE row_id = ?", (stamp(), row_id))

    def mark_failed(self, row_id: int, error: str, *, now_ms: int | None = None) -> dict[str, Any]:
        """Record a delivery failure and schedule the retry, or dead-letter."""
        now_ms = now_ms if now_ms is not None else self.now_ms()
        with self.db.write() as conn:
            row = conn.execute("SELECT attempts FROM outbox WHERE row_id = ?", (row_id,)).fetchone()
            if row is None:
                return {"row_id": row_id, "state": "missing"}
            attempts = int(row["attempts"]) + 1
            if attempts >= self.max_attempts:
                conn.execute("UPDATE outbox SET state = 'dead', attempts = ?, last_error = ?, updated_at = ? WHERE row_id = ?", (attempts, error[:400], stamp(), row_id))
                return {"row_id": row_id, "state": "dead", "attempts": attempts}
            delay_s = min(self.base_backoff_s * (2 ** (attempts - 1)), self.max_backoff_s) * self.jitter()
            conn.execute(
                "UPDATE outbox SET state = 'pending', attempts = ?, next_attempt_ms = ?, last_error = ?, updated_at = ? WHERE row_id = ?",
                (attempts, now_ms + int(delay_s * 1000), error[:400], stamp(), row_id),
            )
        return {"row_id": row_id, "state": "pending", "attempts": attempts, "retry_in_s": round(delay_s, 3)}

    def flush(self, send: Callable[[OutboxMessage], bool], *, limit: int = 32, now_ms: int | None = None) -> dict[str, int]:
        """Attempt one round of delivery. Returns what happened.

        `send` returns True on delivery and False (or raises) otherwise; a
        raise is treated as a failure with the exception type as the reason,
        never as a crash of the drain loop, because one poisonous message
        must not stop every other destination from draining.
        """
        counts = {"attempted": 0, "sent": 0, "retry": 0, "dead": 0}
        for message in self.claim_ready(limit, now_ms):
            counts["attempted"] += 1
            try:
                delivered = bool(send(message))
                error = "" if delivered else "delivery reported failure"
            except Exception as exc:  # noqa: BLE001 - see docstring
                delivered, error = False, f"{exc.__class__.__name__}: {str(exc)[:160]}"
            if delivered:
                self.mark_sent(message.row_id)
                counts["sent"] += 1
            else:
                outcome = self.mark_failed(message.row_id, error, now_ms=now_ms)
                counts["dead" if outcome["state"] == "dead" else "retry"] += 1
        return counts

    # -- inspection --------------------------------------------------------
    def depth(self) -> dict[str, int]:
        rows = self.db.read("SELECT state, COUNT(*) AS n FROM outbox GROUP BY state")
        depths = {row["state"]: int(row["n"]) for row in rows}
        return {state: depths.get(state, 0) for state in ("pending", "inflight", "sent", "dead")}

    def dead_letters(self, limit: int = 50) -> list[dict[str, Any]]:
        return [
            {"message_id": row["message_id"], "destination": row["destination"], "kind": row["kind"], "attempts": int(row["attempts"]), "last_error": row["last_error"], "updated_at": row["updated_at"]}
            for row in self.db.read("SELECT * FROM outbox WHERE state = 'dead' ORDER BY row_id DESC LIMIT ?", (limit,))
        ]

    def requeue_dead(self, message_ids: Iterable[str] | None = None) -> int:
        """Operator action after fixing whatever broke: retry dead letters."""
        now_ms = self.now_ms()
        with self.db.write() as conn:
            if message_ids is None:
                cursor = conn.execute("UPDATE outbox SET state = 'pending', attempts = 0, next_attempt_ms = ?, updated_at = ? WHERE state = 'dead'", (now_ms, stamp()))
                return cursor.rowcount
            total = 0
            for message_id in message_ids:
                cursor = conn.execute(
                    "UPDATE outbox SET state = 'pending', attempts = 0, next_attempt_ms = ?, updated_at = ? WHERE state = 'dead' AND message_id = ?", (now_ms, stamp(), message_id)
                )
                total += cursor.rowcount
            return total

    def purge_sent(self, older_than_s: float = 86_400.0) -> int:
        """Retention: delivered messages are evidence for a while, not forever."""
        cutoff = stamp(datetime.now(UTC) - timedelta(seconds=older_than_s))
        with self.db.write() as conn:
            return conn.execute("DELETE FROM outbox WHERE state = 'sent' AND updated_at < ?", (cutoff,)).rowcount
