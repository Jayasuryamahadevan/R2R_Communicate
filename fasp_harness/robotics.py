"""Conservative fleet-coordination primitives for FASP.

These primitives coordinate space-time reservations. They do not command motors,
replace obstacle avoidance, or bypass a robot's local safety controller.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from .core import FaspError, JsonState


MAX_LEASE_MS = 120_000
MAX_SEGMENTS = 256


class ReservationBook:
    """A durable, conservative cell-and-time reservation arbiter."""

    def __init__(self, state: JsonState) -> None:
        self.state = state

    def _active(self) -> dict[str, dict[str, Any]]:
        now_ms = int(time.time() * 1000)
        reservations = self.state.get("reservations.json", {})
        active = {key: value for key, value in reservations.items() if value["lease_until_ms"] > now_ms and value["state"] == "granted"}
        if active != reservations:
            self.state.put("reservations.json", active)
        return active

    @staticmethod
    def _validate_segments(segments: Any, now_ms: int) -> list[dict[str, Any]]:
        if not isinstance(segments, list) or not 1 <= len(segments) <= MAX_SEGMENTS:
            raise FaspError("schema.invalid", "Reservation needs 1-256 space-time segments.")
        clean = []
        for segment in segments:
            if not isinstance(segment, dict) or not isinstance(segment.get("cell"), str):
                raise FaspError("schema.invalid", "Reservation segment requires a string cell.")
            start, end = segment.get("start_ms"), segment.get("end_ms")
            if not isinstance(start, int) or not isinstance(end, int) or start < now_ms - 2_000 or end <= start or end - start > MAX_LEASE_MS:
                raise FaspError("schema.invalid", "Reservation segment time range is invalid.")
            clean.append({"cell": segment["cell"][:128], "start_ms": start, "end_ms": end})
        return clean

    def request(self, owner: str, payload: dict[str, Any]) -> dict[str, Any]:
        now_ms = int(time.time() * 1000)
        reservation_id = payload.get("reservation_id") or str(uuid.uuid4())
        if not isinstance(reservation_id, str) or len(reservation_id) > 128:
            raise FaspError("schema.invalid", "Reservation ID is invalid.")
        lease_ms = int(payload.get("lease_ms", 30_000))
        if not 1_000 <= lease_ms <= MAX_LEASE_MS:
            raise FaspError("schema.invalid", "Reservation lease must be 1-120 seconds.")
        segments = self._validate_segments(payload.get("segments"), now_ms)
        active = self._active()
        if reservation_id in active:
            existing = active[reservation_id]
            if existing["owner"] == owner:
                return existing
            raise FaspError("fleet.reservation_conflict", "Reservation ID belongs to another robot.")
        for existing in active.values():
            for proposed in segments:
                for held in existing["segments"]:
                    overlap = proposed["cell"] == held["cell"] and proposed["start_ms"] < held["end_ms"] and held["start_ms"] < proposed["end_ms"]
                    if overlap:
                        return {"type": "reservation.reject", "reservation_id": reservation_id, "status": "conflict", "retry_after_ms": max(now_ms + 250, held["end_ms"]), "reason": "space_time_conflict"}
        result = {"type": "reservation.grant", "reservation_id": reservation_id, "owner": owner, "state": "granted", "segments": segments, "lease_until_ms": min(now_ms + lease_ms, max(segment["end_ms"] for segment in segments) + 2_000)}
        active[reservation_id] = result
        self.state.put("reservations.json", active)
        return result

    def release(self, owner: str, reservation_id: str) -> dict[str, Any]:
        active = self._active()
        reservation = active.get(reservation_id)
        if not reservation or reservation["owner"] != owner:
            raise FaspError("fleet.reservation_not_found", "Active reservation is not owned by this robot.")
        reservation["state"] = "released"
        active.pop(reservation_id, None)
        self.state.put("reservations.json", active)
        return {"type": "reservation.released", "reservation_id": reservation_id}


class LocalSafetyGate:
    """A local-only precondition gate that cannot be opened by a network peer."""

    def __init__(self, maximum_speed_mps: float) -> None:
        self.maximum_speed_mps = maximum_speed_mps

    def validate(self, requested_speed_mps: float, estop_clear: bool, obstacle_clear: bool, localization_healthy: bool, reservation_active: bool) -> None:
        if not estop_clear:
            raise FaspError("safety.estop_active", "Local emergency stop is active.")
        if not obstacle_clear or not localization_healthy:
            raise FaspError("safety.precondition_failed", "Local obstacle or localization precondition failed.")
        if not reservation_active:
            raise FaspError("safety.precondition_failed", "No active local route reservation.")
        if not 0 <= requested_speed_mps <= self.maximum_speed_mps:
            raise FaspError("safety.speed_limit", "Requested speed exceeds local safety envelope.")
