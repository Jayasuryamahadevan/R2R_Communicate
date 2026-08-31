"""Fleet space-time reservation state (`reservations` / `reservation_segments`
tables). See fasp_harness/robotics.py for validation and the public
request()/release() API built on top of this.
"""

from __future__ import annotations

from typing import Any

from .db import Database


class ReservationsRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get_active(self, reservation_id: str, now_ms: int) -> dict[str, Any] | None:
        row = self.db.read_one(
            "SELECT * FROM reservations WHERE reservation_id = ? AND state = 'granted' AND lease_until_ms > ?",
            (reservation_id, now_ms),
        )
        if row is None:
            return None
        return self._with_segments(row)

    def find_conflict(self, segments: list[dict[str, Any]], now_ms: int) -> dict[str, Any] | None:
        """Return the first currently-held segment overlapping any of
        `segments`, or None. One indexed range query per proposed segment."""
        for proposed in segments:
            row = self.db.read_one(
                "SELECT reservation_segments.* FROM reservation_segments "
                "JOIN reservations ON reservations.reservation_id = reservation_segments.reservation_id "
                "WHERE reservations.state = 'granted' AND reservations.lease_until_ms > ? "
                "AND reservation_segments.cell = ? AND reservation_segments.start_ms < ? AND reservation_segments.end_ms > ? "
                "LIMIT 1",
                (now_ms, proposed["cell"], proposed["end_ms"], proposed["start_ms"]),
            )
            if row is not None:
                return {"cell": row["cell"], "start_ms": row["start_ms"], "end_ms": row["end_ms"]}
        return None

    def grant(self, reservation_id: str, owner: str, segments: list[dict[str, Any]], lease_until_ms: int) -> None:
        """Grant (or renew, if `reservation_id` previously existed but is
        no longer active) a reservation. Renewal replaces its segments."""
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO reservations (reservation_id, owner, state, lease_until_ms) VALUES (?, ?, 'granted', ?) "
                "ON CONFLICT(reservation_id) DO UPDATE SET owner = excluded.owner, state = 'granted', lease_until_ms = excluded.lease_until_ms",
                (reservation_id, owner, lease_until_ms),
            )
            conn.execute("DELETE FROM reservation_segments WHERE reservation_id = ?", (reservation_id,))
            for segment in segments:
                conn.execute(
                    "INSERT INTO reservation_segments (reservation_id, cell, start_ms, end_ms) VALUES (?, ?, ?, ?)",
                    (reservation_id, segment["cell"], segment["start_ms"], segment["end_ms"]),
                )

    def release(self, owner: str, reservation_id: str, now_ms: int) -> bool:
        with self.db.write() as conn:
            cursor = conn.execute(
                "UPDATE reservations SET state = 'released' WHERE reservation_id = ? AND owner = ? AND state = 'granted' AND lease_until_ms > ?",
                (reservation_id, owner, now_ms),
            )
            return cursor.rowcount > 0

    def sweep_expired(self, now_ms: int) -> None:
        """Delete reservations (and their segments) that are released or
        past their lease -- mirrors the eager pruning the JSON-file
        ReservationBook used to do on every read, so storage stays bounded
        to currently-relevant reservations rather than growing over the
        life of the harness."""
        with self.db.write() as conn:
            stale = conn.execute("SELECT reservation_id FROM reservations WHERE state != 'granted' OR lease_until_ms <= ?", (now_ms,)).fetchall()
            for row in stale:
                conn.execute("DELETE FROM reservation_segments WHERE reservation_id = ?", (row["reservation_id"],))
                conn.execute("DELETE FROM reservations WHERE reservation_id = ?", (row["reservation_id"],))

    def _with_segments(self, row: Any) -> dict[str, Any]:
        segments = self.db.read(
            "SELECT cell, start_ms, end_ms FROM reservation_segments WHERE reservation_id = ?",
            (row["reservation_id"],),
        )
        return {
            "reservation_id": row["reservation_id"],
            "owner": row["owner"],
            "state": row["state"],
            "lease_until_ms": row["lease_until_ms"],
            "segments": [{"cell": segment["cell"], "start_ms": segment["start_ms"], "end_ms": segment["end_ms"]} for segment in segments],
        }
