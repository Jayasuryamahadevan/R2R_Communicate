"""Durable mission state (`missions` table).

Missions are the one piece of Layer 3 state that must survive a crash
intact: a mission recorded as dispatched but lost from memory becomes a
robot executing work nobody is tracking, and a mission accepted but never
recorded becomes a request that silently evaporated. So the durable record
is written *before* the vehicle is told anything, and every state change is
a guarded compare-and-set on the state it is leaving -- never a blind
UPDATE -- so two concurrent reconcilers cannot walk a mission backwards.
"""

from __future__ import annotations

import json
from typing import Any

from ..timestamps import stamp
from .db import Database

TERMINAL_MISSION_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED", "REJECTED"})
ACTIVE_MISSION_STATES = frozenset({"ACCEPTED", "PREFLIGHT", "ASSIGNED", "RUNNING", "PAUSED"})


def _row(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "mission_id": row["mission_id"],
        "requested_by": row["requested_by"],
        "fleet": row["fleet"],
        "vehicle_id": row["vehicle_id"],
        "state": row["state"],
        "priority": int(row["priority"]),
        "definition": json.loads(row["definition_json"]),
        "preflight": json.loads(row["preflight_json"]) if row["preflight_json"] else None,
        "result": json.loads(row["result_json"]) if row["result_json"] else None,
        "error": json.loads(row["error_json"]) if row["error_json"] else None,
        "fence": int(row["fence"]) if row["fence"] is not None else None,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "dispatched_at": row["dispatched_at"],
        "deadline_at": row["deadline_at"],
    }


class MissionsRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def accept(self, mission_id: str, requested_by: str, definition: dict[str, Any], *, priority: int = 0, fleet: str | None = None, deadline_at: str | None = None) -> bool:
        """Record a new mission. False means this id already exists, which
        makes a retried submission idempotent rather than a second robot."""
        with self.db.write() as conn:
            if conn.execute("SELECT 1 FROM missions WHERE mission_id = ?", (mission_id,)).fetchone() is not None:
                return False
            conn.execute(
                "INSERT INTO missions (mission_id, requested_by, fleet, vehicle_id, state, priority, definition_json, created_at, updated_at, deadline_at) "
                "VALUES (?, ?, ?, NULL, 'ACCEPTED', ?, ?, ?, ?, ?)",
                (mission_id, requested_by, fleet, priority, json.dumps(definition, sort_keys=True), stamp(), stamp(), deadline_at),
            )
        return True

    def get(self, mission_id: str) -> dict[str, Any] | None:
        return _row(self.db.read_one("SELECT * FROM missions WHERE mission_id = ?", (mission_id,)))

    def transition(self, mission_id: str, expected: set[str], new_state: str, **columns: Any) -> bool:
        """Guarded state change: only from one of `expected`."""
        assignments = ["state = ?", "updated_at = ?"]
        values: list[Any] = [new_state, stamp()]
        for column, value in sorted(columns.items()):
            assignments.append(f"{column} = ?")
            values.append(json.dumps(value, sort_keys=True) if column.endswith("_json") and value is not None else value)
        placeholders = ", ".join("?" for _ in expected)
        with self.db.write() as conn:
            cursor = conn.execute(
                f"UPDATE missions SET {', '.join(assignments)} WHERE mission_id = ? AND state IN ({placeholders})",  # noqa: S608 - column names are literals above, values are bound
                (*values, mission_id, *sorted(expected)),
            )
            return cursor.rowcount > 0

    def assign(self, mission_id: str, vehicle_id: str, fleet: str, fence: int | None, preflight: dict[str, Any] | None) -> bool:
        return self.transition(
            mission_id,
            {"ACCEPTED", "PREFLIGHT"},
            "ASSIGNED",
            vehicle_id=vehicle_id,
            fleet=fleet,
            fence=fence,
            preflight_json=preflight,
            dispatched_at=stamp(),
        )

    def finish(self, mission_id: str, state: str, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> bool:
        return self.transition(mission_id, set(ACTIVE_MISSION_STATES), state, result_json=result, error_json=error)

    def active(self, limit: int = 500) -> list[dict[str, Any]]:
        placeholders = ", ".join("?" for _ in ACTIVE_MISSION_STATES)
        rows = self.db.read(
            f"SELECT * FROM missions WHERE state IN ({placeholders}) ORDER BY priority DESC, created_at LIMIT ?",  # noqa: S608 - placeholders only
            (*sorted(ACTIVE_MISSION_STATES), limit),
        )
        return [entry for entry in (_row(row) for row in rows) if entry is not None]

    def for_vehicle(self, vehicle_id: str) -> list[dict[str, Any]]:
        rows = self.db.read("SELECT * FROM missions WHERE vehicle_id = ? ORDER BY updated_at DESC LIMIT 50", (vehicle_id,))
        return [entry for entry in (_row(row) for row in rows) if entry is not None]

    def counts(self) -> dict[str, int]:
        return {row["state"]: int(row["n"]) for row in self.db.read("SELECT state, COUNT(*) AS n FROM missions GROUP BY state")}
