"""Fleet mission projection over the shared durable work-item store.

Mission-specific fields stay in payload and metadata. Their familiar states
are projections of the common queued/running/terminal lifecycle plus a phase.
"""

from __future__ import annotations

import json
from typing import Any

from ..timestamps import stamp
from .db import Database
from .work_items_repo import WorkItemsRepo, WorkState

TERMINAL_MISSION_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED", "REJECTED"})
ACTIVE_MISSION_STATES = frozenset({"ACCEPTED", "PREFLIGHT", "ASSIGNED", "RUNNING", "PAUSED"})

_STATE_TO_LIFECYCLE = {
    "ACCEPTED": WorkState.QUEUED.value,
    "PREFLIGHT": WorkState.QUEUED.value,
    "ASSIGNED": WorkState.RUNNING.value,
    "RUNNING": WorkState.RUNNING.value,
    "PAUSED": WorkState.RUNNING.value,
    "COMPLETED": WorkState.SUCCEEDED.value,
    "FAILED": WorkState.FAILED.value,
    "CANCELLED": WorkState.CANCELLED.value,
    "REJECTED": WorkState.FAILED.value,
}


def _mission_state(item: dict[str, Any]) -> str:
    if item["state"] == "succeeded":
        return "COMPLETED"
    if item["state"] == "cancelled":
        return "CANCELLED"
    if item["state"] == "failed":
        return "REJECTED" if item["phase"] == "rejected" else "FAILED"
    phase = "assigned" if item["phase"] == "dispatching" else item["phase"]
    return str(phase or ("ACCEPTED" if item["state"] == "queued" else "RUNNING")).upper()


def _row(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if item is None:
        return None
    metadata = item["metadata"]
    return {
        "mission_id": item["work_id"].removeprefix("mission:"),
        "requested_by": item["owner"],
        "fleet": metadata.get("fleet"),
        "vehicle_id": item["assigned_to"] or metadata.get("vehicle_id"),
        "state": _mission_state(item),
        "status": item["state"],
        "phase": item["phase"],
        "priority": item["priority"],
        "definition": item["payload"] or {},
        "preflight": metadata.get("preflight"),
        "result": item["result"],
        "error": item["error"],
        "fence": item["fence"],
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
        "dispatched_at": item["dispatched_at"],
        "deadline_at": item["deadline_at"],
    }


class MissionsRepo:
    def __init__(self, db: Database, work_items: WorkItemsRepo | None = None) -> None:
        self.db = db
        self.work_items = work_items or WorkItemsRepo(db)

    def accept(
        self,
        mission_id: str,
        requested_by: str,
        definition: dict[str, Any],
        *,
        priority: int = 0,
        fleet: str | None = None,
        deadline_at: str | None = None,
    ) -> bool:
        at = stamp()
        return self.work_items.create(
            work_id=f"mission:{mission_id}",
            kind="mission",
            owner=requested_by,
            idempotency_key=mission_id,
            payload=definition,
            metadata={"fleet": fleet, "vehicle_id": None, "preflight": None},
            priority=priority,
            deadline_at=deadline_at,
            phase="accepted",
            at=at,
        )

    def get(self, mission_id: str) -> dict[str, Any] | None:
        return _row(self.work_items.get(f"mission:{mission_id}", "mission"))

    def transition(self, mission_id: str, expected: set[str], new_state: str, **columns: Any) -> bool:
        lifecycle_states = {_STATE_TO_LIFECYCLE[state] for state in expected if state in _STATE_TO_LIFECYCLE}
        phases = {state.lower() for state in expected if state in _STATE_TO_LIFECYCLE}
        lifecycle_state = _STATE_TO_LIFECYCLE[new_state]
        target_phase = columns.pop("phase", new_state.lower())
        expected_phases = columns.pop("expected_phases", phases)

        metadata_patch: dict[str, Any] = {}
        for column in ("fleet", "vehicle_id", "preflight_json"):
            if column not in columns:
                continue
            value = columns.pop(column)
            key = "preflight" if column == "preflight_json" else column
            metadata_patch[key] = json.loads(value) if column == "preflight_json" and isinstance(value, str) else value

        kwargs: dict[str, Any] = {
            "phase": target_phase,
            "metadata_patch": metadata_patch,
        }
        if "result_json" in columns:
            value = columns.pop("result_json")
            kwargs["result"] = json.loads(value) if isinstance(value, str) else value
        if "error_json" in columns:
            value = columns.pop("error_json")
            kwargs["error"] = json.loads(value) if isinstance(value, str) else value
        if "vehicle_id" in metadata_patch:
            kwargs["assigned_to"] = metadata_patch["vehicle_id"]
        if "fence" in columns:
            kwargs["fence"] = columns.pop("fence")
        if "dispatched_at" in columns:
            kwargs["dispatched_at"] = columns.pop("dispatched_at")
        if columns:
            raise ValueError(f"Unsupported mission fields: {', '.join(sorted(columns))}")

        return self.work_items.transition(
            f"mission:{mission_id}",
            "mission",
            lifecycle_states,
            lifecycle_state,
            stamp(),
            expected_phases=expected_phases,
            **kwargs,
        )

    def prepare_dispatch(
        self,
        mission_id: str,
        vehicle_id: str,
        fleet: str,
        fence: int | None,
        preflight: dict[str, Any] | None,
    ) -> bool:
        return self.transition(
            mission_id,
            {"ACCEPTED", "PREFLIGHT"},
            "RUNNING",
            phase="dispatching",
            vehicle_id=vehicle_id,
            fleet=fleet,
            fence=fence,
            preflight_json=preflight,
            dispatched_at=stamp(),
        )

    def mark_assigned(self, mission_id: str) -> bool:
        return self.transition(
            mission_id,
            {"RUNNING"},
            "ASSIGNED",
            expected_phases={"dispatching"},
        )

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
        columns: dict[str, Any] = {}
        if result is not None:
            columns["result_json"] = result
        if error is not None:
            columns["error_json"] = error
        columns["expected_phases"] = {phase.lower() for phase in ACTIVE_MISSION_STATES} | {"dispatching"}
        return self.transition(mission_id, set(ACTIVE_MISSION_STATES), state, **columns)

    def active(self, limit: int = 500) -> list[dict[str, Any]]:
        return [item for item in (_row(row) for row in self.work_items.active("mission", limit)) if item is not None]

    def for_vehicle(self, vehicle_id: str) -> list[dict[str, Any]]:
        return [item for item in (_row(row) for row in self.work_items.for_assignee("mission", vehicle_id)) if item is not None]

    def counts(self) -> dict[str, int]:
        rows = self.db.read(
            "SELECT state, phase, COUNT(*) AS n FROM work_items WHERE kind = 'mission' GROUP BY state, phase"
        )
        counts: dict[str, int] = {}
        for row in rows:
            if row["state"] == "succeeded":
                state = "COMPLETED"
            elif row["state"] == "cancelled":
                state = "CANCELLED"
            elif row["state"] == "failed":
                state = "REJECTED" if row["phase"] == "rejected" else "FAILED"
            else:
                phase = "assigned" if row["phase"] == "dispatching" else row["phase"]
                state = str(phase or ("accepted" if row["state"] == "queued" else "running")).upper()
            counts[state] = counts.get(state, 0) + int(row["n"])
        return counts
