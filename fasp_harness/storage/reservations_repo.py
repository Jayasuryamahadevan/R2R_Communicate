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

    def request_atomic(
        self,
        reservation_id: str,
        owner: str,
        segments: list[dict[str, Any]],
        lease_until_ms: int,
        now_ms: int,
    ) -> dict[str, Any] | None:
        """Check for a conflict (an existing reservation under this ID, or
        an overlapping segment held by someone else) and grant if there is
        none -- all inside ONE `db.write()` transaction.

        This used to be two separate calls (`find_conflict()` then
        `grant()`), each acquiring and releasing `Database`'s lock on its
        own -- exactly the TOCTOU window `db.write()`'s own docstring
        says it exists to close ("lets a repo do a check-then-insert
        without a TOCTOU window"), just not actually used that way here.
        Two genuinely concurrent requests for the same overlapping
        segment could each pass the conflict check before either
        committed its grant, and both would be granted -- confirmed by
        running exactly that scenario for real (three concurrent
        requests contending for one cell) before this fix existed.

        Returns None on success (granted). Otherwise a dict describing
        why not: `{"kind": "existing", "owner": ...}` if `reservation_id`
        is already active (for a DIFFERENT owner than that -- `request()`
        decides what that means), or `{"kind": "conflict", "cell":
        ..., "start_ms": ..., "end_ms": ...}` for an overlapping segment
        held by someone else.
        """
        with self.db.write() as conn:
            existing = conn.execute(
                "SELECT * FROM reservations WHERE reservation_id = ? AND state = 'granted' AND lease_until_ms > ?",
                (reservation_id, now_ms),
            ).fetchone()
            if existing is not None:
                return {"kind": "existing", "owner": existing["owner"]}

            for proposed in segments:
                conflict_row = self._find_conflict(conn, proposed, now_ms)
                if conflict_row is not None:
                    return {
                        "kind": "conflict",
                        "cell": conflict_row["cell"],
                        "start_ms": conflict_row["start_ms"],
                        "end_ms": conflict_row["end_ms"],
                        "basis": "volume" if conflict_row["cell"] != proposed["cell"] else "cell",
                    }

            conn.execute(
                "INSERT INTO reservations (reservation_id, owner, state, lease_until_ms) VALUES (?, ?, 'granted', ?) "
                "ON CONFLICT(reservation_id) DO UPDATE SET owner = excluded.owner, state = 'granted', lease_until_ms = excluded.lease_until_ms",
                (reservation_id, owner, lease_until_ms),
            )
            conn.execute("DELETE FROM reservation_segments WHERE reservation_id = ?", (reservation_id,))
            for segment in segments:
                volume = segment.get("volume")
                conn.execute(
                    "INSERT INTO reservation_segments "
                    "(reservation_id, cell, start_ms, end_ms, guard_start_ms, guard_end_ms, frame_id, min_x, min_y, min_z, max_x, max_y, max_z) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        reservation_id,
                        segment["cell"],
                        segment["start_ms"],
                        segment["end_ms"],
                        segment["start_ms"] - segment.get("guard_ms", 0),
                        segment["end_ms"] + segment.get("guard_ms", 0),
                        volume["frame_id"] if volume else None,
                        *(volume["minimum_m"] if volume else (None, None, None)),
                        *(volume["maximum_m"] if volume else (None, None, None)),
                    ),
                )
            return None

    @staticmethod
    def _find_conflict(conn: Any, proposed: dict[str, Any], now_ms: int) -> Any:
        """An active segment overlapping `proposed` in dilated space-time.

        Time is compared guard-to-guard: both sides carry their own clock
        uncertainty, and two segments are apart only if they are apart
        after both have been widened. Space is the union of the two
        vocabularies -- the same cell name, or an overlapping box in the
        same frame -- so a deployment can use either, or both, and a
        reservation written by a robot that shares no cell vocabulary with
        its peer still conflicts with them physically.
        """
        guard_ms = proposed.get("guard_ms", 0)
        window = (proposed["end_ms"] + guard_ms, proposed["start_ms"] - guard_ms)
        volume = proposed.get("volume")

        row = conn.execute(
            "SELECT reservation_segments.* FROM reservation_segments "
            "JOIN reservations ON reservations.reservation_id = reservation_segments.reservation_id "
            "WHERE reservations.state = 'granted' AND reservations.lease_until_ms > ? "
            "AND reservation_segments.guard_start_ms < ? AND reservation_segments.guard_end_ms > ? "
            "AND reservation_segments.cell = ? LIMIT 1",
            (now_ms, *window, proposed["cell"]),
        ).fetchone()
        if row is not None or volume is None:
            return row

        minimum, maximum = volume["minimum_m"], volume["maximum_m"]
        return conn.execute(
            "SELECT reservation_segments.* FROM reservation_segments "
            "JOIN reservations ON reservations.reservation_id = reservation_segments.reservation_id "
            "WHERE reservations.state = 'granted' AND reservations.lease_until_ms > ? "
            "AND reservation_segments.guard_start_ms < ? AND reservation_segments.guard_end_ms > ? "
            "AND reservation_segments.frame_id = ? "
            "AND reservation_segments.min_x < ? AND reservation_segments.max_x > ? "
            "AND reservation_segments.min_y < ? AND reservation_segments.max_y > ? "
            "AND reservation_segments.min_z < ? AND reservation_segments.max_z > ? LIMIT 1",
            (
                now_ms,
                *window,
                volume["frame_id"],
                maximum[0], minimum[0],
                maximum[1], minimum[1],
                maximum[2], minimum[2],
            ),
        ).fetchone()

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
            "SELECT cell, start_ms, end_ms, guard_start_ms, guard_end_ms, frame_id, min_x, min_y, min_z, max_x, max_y, max_z "
            "FROM reservation_segments WHERE reservation_id = ?",
            (row["reservation_id"],),
        )
        return {
            "reservation_id": row["reservation_id"],
            "owner": row["owner"],
            "state": row["state"],
            "lease_until_ms": row["lease_until_ms"],
            "segments": [_row_to_segment(segment) for segment in segments],
        }


def _row_to_segment(row: Any) -> dict[str, Any]:
    """Report the requested window and the dilated one separately.

    An operator reading a reservation needs both: what was asked for, and
    the wider window the arbiter actually enforced on its behalf. Folding
    them together would make a granted reservation look like it had
    claimed more than the requester asked.
    """
    segment: dict[str, Any] = {"cell": row["cell"], "start_ms": row["start_ms"], "end_ms": row["end_ms"]}
    if row["guard_start_ms"] is not None:
        segment["guard_ms"] = row["start_ms"] - row["guard_start_ms"]
        segment["guard_start_ms"] = row["guard_start_ms"]
        segment["guard_end_ms"] = row["guard_end_ms"]
    if row["frame_id"] is not None:
        segment["volume"] = {
            "frame_id": row["frame_id"],
            "minimum_m": [row["min_x"], row["min_y"], row["min_z"]],
            "maximum_m": [row["max_x"], row["max_y"], row["max_z"]],
        }
    return segment
