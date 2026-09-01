"""Conservative fleet-coordination primitives for FASP.

These primitives coordinate space-time reservations. They do not command motors,
replace obstacle avoidance, or bypass a robot's local safety controller.

Reservations are *dilated* before they are compared. The exact test --
same cell name, same millisecond range -- is the right property for a
ledger and the wrong one for two machines that disagree about the time
and do not know precisely where they are. A segment may therefore carry:

    guard_ms   the requester's own clock uncertainty plus its decision
               margin, widening the segment at both ends. Two segments
               are apart only once both have been widened, so two
               reservations ten milliseconds apart on paper, held by
               owners whose clocks disagree by two hundred, correctly
               conflict.

    volume     an axis-aligned box in a named frame, already dilated by
               the requester's guard band. A cell name is a convention
               two vendors must first agree on; a box in a named frame is
               not, so robots that share no cell vocabulary can still
               conflict physically.

Both are optional and a segment without them behaves exactly as before.
`fasp_harness/spatial/reservation.py` builds them from a state report, so
the guard band and the reservation are the same number rather than two
that drift apart.
"""

from __future__ import annotations

import math
import time
import uuid
from typing import Any

from .protocol.errors import FaspError
from .storage.reservations_repo import ReservationsRepo

MAX_LEASE_MS = 120_000
MAX_SEGMENTS = 256

# A guard is a correction for uncertainty, not a way to claim the site. A
# robot that declares thirty seconds of clock doubt has a clock problem to
# fix, not a larger reservation to be granted.
MAX_GUARD_MS = 30_000

# Likewise for space: a kilometre in any axis is far beyond any floor this
# coordinates, and the cap is what stops one bad covariance from reserving
# the whole frame.
MAX_VOLUME_EXTENT_M = 1_000.0


class ReservationBook:
    """A durable, conservative cell-and-time reservation arbiter."""

    def __init__(self, repo: ReservationsRepo) -> None:
        self.repo = repo

    @staticmethod
    def _validate_volume(volume: Any) -> dict[str, Any] | None:
        """Parse and bound an optional reservation volume.

        Bounded in extent because a guard band is derived from a
        covariance, and a covariance can be enormous -- a robot that has
        been silent for a minute has a legitimate claim to a very large
        box, and granting it would let one stale peer reserve the site.
        The cap converts that into a refusal the operator can see.
        """
        if volume is None:
            return None
        if not isinstance(volume, dict) or not isinstance(volume.get("frame_id"), str) or not volume["frame_id"]:
            raise FaspError("schema.invalid", "A reservation volume needs a frame_id.")
        minimum, maximum = volume.get("minimum_m"), volume.get("maximum_m")
        if not isinstance(minimum, list) or not isinstance(maximum, list) or len(minimum) != 3 or len(maximum) != 3:
            raise FaspError("schema.invalid", "A reservation volume needs three-element minimum_m and maximum_m.")
        try:
            low = [float(value) for value in minimum]
            high = [float(value) for value in maximum]
        except (TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "Reservation volume bounds must be numbers.") from error
        if not all(math.isfinite(value) for value in low + high):
            raise FaspError("schema.invalid", "Reservation volume bounds must be finite.")
        if any(a >= b for a, b in zip(low, high, strict=True)):
            raise FaspError("schema.invalid", "Every reservation volume axis must have positive extent.")
        if any(b - a > MAX_VOLUME_EXTENT_M for a, b in zip(low, high, strict=True)):
            raise FaspError("schema.invalid", f"A reservation volume may not exceed {MAX_VOLUME_EXTENT_M:g} m in any axis.")
        return {"frame_id": volume["frame_id"][:128], "minimum_m": low, "maximum_m": high}

    @classmethod
    def _validate_segments(cls, segments: Any, now_ms: int) -> list[dict[str, Any]]:
        if not isinstance(segments, list) or not 1 <= len(segments) <= MAX_SEGMENTS:
            raise FaspError("schema.invalid", "Reservation needs 1-256 space-time segments.")
        clean = []
        for segment in segments:
            if not isinstance(segment, dict) or not isinstance(segment.get("cell"), str):
                raise FaspError("schema.invalid", "Reservation segment requires a string cell.")
            start, end = segment.get("start_ms"), segment.get("end_ms")
            if not isinstance(start, int) or not isinstance(end, int) or start < now_ms - 2_000 or end <= start or end - start > MAX_LEASE_MS:
                raise FaspError("schema.invalid", "Reservation segment time range is invalid.")
            guard = segment.get("guard_ms", 0)
            if isinstance(guard, bool) or not isinstance(guard, int | float) or not math.isfinite(guard) or not 0 <= guard <= MAX_GUARD_MS:
                raise FaspError("schema.invalid", f"A reservation guard must be 0-{MAX_GUARD_MS} ms; a larger one is a clock fault, not a bigger reservation.")
            clean.append(
                {
                    "cell": segment["cell"][:128],
                    "start_ms": start,
                    "end_ms": end,
                    "guard_ms": int(guard),
                    "volume": cls._validate_volume(segment.get("volume")),
                }
            )
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

        # The lease must outlast the widened window, not the requested one:
        # a reservation whose guard band extends past its own lease would
        # be released while it was still excluding other traffic.
        lease_until_ms = min(now_ms + lease_ms, max(segment["end_ms"] + segment["guard_ms"] for segment in segments) + 2_000)

        # One atomic check-then-grant (see request_atomic()'s own
        # docstring for why this must not be two separate calls).
        outcome = self.repo.request_atomic(reservation_id, owner, segments, lease_until_ms, now_ms)
        if outcome is None:
            return {"type": "reservation.grant", "reservation_id": reservation_id, "owner": owner, "state": "granted", "segments": segments, "lease_until_ms": lease_until_ms}
        if outcome["kind"] == "existing":
            if outcome["owner"] == owner:
                existing = self.repo.get_active(reservation_id, now_ms)
                return {"type": "reservation.grant", **existing}
            raise FaspError("fleet.reservation_conflict", "Reservation ID belongs to another robot.")
        return {
            "type": "reservation.reject",
            "reservation_id": reservation_id,
            "status": "conflict",
            "retry_after_ms": max(now_ms + 250, outcome["end_ms"]),
            "reason": "space_time_conflict",
            # Which test caught it: a shared cell name, or two guard bands
            # that physically overlap. An operator debugging a livelock
            # needs to know whether the cell map or the geometry is at
            # fault, and they are different problems.
            "basis": outcome.get("basis", "cell"),
        }

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
