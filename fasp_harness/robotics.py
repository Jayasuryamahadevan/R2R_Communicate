"""Conservative fleet-coordination primitives for FASP.

These primitives coordinate space-time reservations. They do not command motors,
replace obstacle avoidance, or bypass a robot's local safety controller.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from .protocol.errors import FaspError
from .storage.reservations_repo import ReservationsRepo


MAX_LEASE_MS = 120_000
MAX_SEGMENTS = 256


class ReservationBook:
    """A durable, conservative cell-and-time reservation arbiter."""

    def __init__(self, repo: ReservationsRepo) -> None:
        self.repo = repo

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
        self.repo.sweep_expired(now_ms)
        reservation_id = payload.get("reservation_id") or str(uuid.uuid4())
        if not isinstance(reservation_id, str) or len(reservation_id) > 128:
            raise FaspError("schema.invalid", "Reservation ID is invalid.")
        lease_ms = int(payload.get("lease_ms", 30_000))
        if not 1_000 <= lease_ms <= MAX_LEASE_MS:
            raise FaspError("schema.invalid", "Reservation lease must be 1-120 seconds.")
        segments = self._validate_segments(payload.get("segments"), now_ms)

        existing = self.repo.get_active(reservation_id, now_ms)
        if existing is not None:
            if existing["owner"] == owner:
                return {"type": "reservation.grant", **existing}
            raise FaspError("fleet.reservation_conflict", "Reservation ID belongs to another robot.")

        conflict = self.repo.find_conflict(segments, now_ms)
        if conflict is not None:
            return {"type": "reservation.reject", "reservation_id": reservation_id, "status": "conflict", "retry_after_ms": max(now_ms + 250, conflict["end_ms"]), "reason": "space_time_conflict"}

        lease_until_ms = min(now_ms + lease_ms, max(segment["end_ms"] for segment in segments) + 2_000)
        self.repo.grant(reservation_id, owner, segments, lease_until_ms)
        return {"type": "reservation.grant", "reservation_id": reservation_id, "owner": owner, "state": "granted", "segments": segments, "lease_until_ms": lease_until_ms}

    def release(self, owner: str, reservation_id: str) -> dict[str, Any]:
        now_ms = int(time.time() * 1000)
        if not self.repo.release(owner, reservation_id, now_ms):
            raise FaspError("fleet.reservation_not_found", "Active reservation is not owned by this robot.")
        return {"type": "reservation.released", "reservation_id": reservation_id}


class LocalSafetyGate:
    """A local precondition gate. Its ONE network-writable operation is
    request_halt() -- asking a machine to stop is always safe to honor
    immediately. Nothing reachable from a network peer can clear a halt or
    loosen any other precondition; only local code calling clear_halt()
    can (FASP_PROTOCOL.md ss9.1: "an out-of-band physical emergency stop
    MUST remain effective if the network, relay, model, or FASP peer
    fails")."""

    def __init__(self, maximum_speed_mps: float) -> None:
        self.maximum_speed_mps = maximum_speed_mps
        self._halt_requested = False
        self._halt_reason: str | None = None
        self._last_check: dict[str, Any] | None = None

    def request_halt(self, reason: str) -> None:
        self._halt_requested = True
        self._halt_reason = reason

    def clear_halt(self) -> None:
        """Local-only: never call this from a network-facing handler."""
        self._halt_requested = False
        self._halt_reason = None

    def status(self) -> dict[str, Any]:
        return {"halt_requested": self._halt_requested, "halt_reason": self._halt_reason, "last_check": self._last_check}

    def validate(self, requested_speed_mps: float, estop_clear: bool, obstacle_clear: bool, localization_healthy: bool, reservation_active: bool) -> None:
        self._last_check = {
            "estop_clear": estop_clear,
            "obstacle_clear": obstacle_clear,
            "localization_healthy": localization_healthy,
            "reservation_active": reservation_active,
            "requested_speed_mps": requested_speed_mps,
        }
        if self._halt_requested:
            raise FaspError("safety.estop_active", f"Halt requested: {self._halt_reason or 'no reason given'}.")
        if not estop_clear:
            raise FaspError("safety.estop_active", "Local emergency stop is active.")
        if not obstacle_clear or not localization_healthy:
            raise FaspError("safety.precondition_failed", "Local obstacle or localization precondition failed.")
        if not reservation_active:
            raise FaspError("safety.precondition_failed", "No active local route reservation.")
        if not 0 <= requested_speed_mps <= self.maximum_speed_mps:
            raise FaspError("safety.speed_limit", "Requested speed exceeds local safety envelope.")
