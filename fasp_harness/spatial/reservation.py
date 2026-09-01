"""Turning a guard band into a space-time reservation.

`fasp_harness/robotics.py` arbitrates reservations; `guard.py` computes how
much space a robot might actually occupy. This module is the seam, and it
exists so those two are the *same* number rather than two numbers that
drift apart.

That drift is a real failure mode and an unpleasant one, because both
halves look right in isolation. A fleet manager sizes a guard band from a
covariance, then reserves a cell chosen from a map drawn by hand a year
earlier. The band and the reservation now disagree, the reservation is
what the arbiter enforces, and the band is what the operator was shown.
Nobody notices until two robots meet inside a cell that was granted to
one of them.

Two things are carried across:

    the box     the envelope's half-extents become the reservation volume,
                so what is reserved is what might be occupied

    the guard   the clock uncertainty that stamped the report, plus the
                decision margin, becomes the segment's temporal dilation

The second matters more than it looks. A reservation is a claim about
*when* as much as where, and the claim is being made by a machine whose
clock is only approximately the arbiter's. Widening the segment by that
uncertainty is what makes "these two reservations do not overlap" a
statement about the world rather than about two disagreeing clocks.
"""

from __future__ import annotations

import math
from typing import Any

from ..protocol.errors import FaspError
from ..robotics import MAX_GUARD_MS, MAX_VOLUME_EXTENT_M
from .guard import Envelope, GuardPolicy, Morphology, envelope_for
from .state import StateReport

__all__ = ["segment_from_envelope", "segments_for_occupancy", "reserve_occupancy"]


def segment_from_envelope(
    envelope: Envelope,
    *,
    start_ms: int,
    end_ms: int,
    cell: str,
    guard_ms: float,
) -> dict[str, Any]:
    """One reservation segment covering everywhere `envelope` might reach.

    `cell` is still required, because the existing arbiter is indexed on
    it and a deployment with a working cell map should keep using it. The
    volume rides alongside: a cell name is a convention two vendors have
    to agree on first, and a box in a named frame is not, so a robot that
    shares no cell vocabulary with its peer still conflicts with it
    physically.
    """
    if end_ms <= start_ms:
        raise FaspError("schema.invalid", "A reservation segment must end after it begins.")
    if not math.isfinite(guard_ms) or guard_ms < 0.0:
        raise FaspError("schema.invalid", "A reservation guard must be finite and non-negative.")
    if guard_ms > MAX_GUARD_MS:
        raise FaspError(
            "schema.invalid",
            f"A {guard_ms:.0f} ms guard exceeds the {MAX_GUARD_MS} ms cap; that is a clock fault to fix, not a larger reservation to grant.",
        )

    extents = [2.0 * extent for extent in envelope.half_extents_m]
    if any(extent > MAX_VOLUME_EXTENT_M for extent in extents):
        widest = max(extents)
        raise FaspError(
            "schema.invalid",
            f"The guard band spans {widest:.1f} m, beyond the {MAX_VOLUME_EXTENT_M:g} m reservation cap; "
            "the report is too stale or too uncertain to reserve against.",
        )

    return {
        "cell": cell,
        "start_ms": int(start_ms),
        "end_ms": int(end_ms),
        "guard_ms": int(round(guard_ms)),
        "volume": {
            "frame_id": envelope.frame_id,
            "minimum_m": envelope.minimum_m(),
            "maximum_m": envelope.maximum_m(),
        },
    }


def segments_for_occupancy(
    report: StateReport,
    policy: GuardPolicy,
    *,
    morphology: Morphology,
    cell: str,
    start_ms: int,
    end_ms: int,
    body_radius_m: float = 0.0,
    steps: int = 4,
) -> list[dict[str, Any]]:
    """Reserve the corridor a robot sweeps out, not a single snapshot.

    A reservation covering only where the robot is now is wrong in the
    obvious way: it is a claim about a window of time, and the robot moves
    during it. Sampling the envelope at several instants and reserving
    each keeps the claim honest, and because the envelope widens with age
    the later samples are automatically larger -- the corridor is a cone,
    not a tube, which is exactly the right shape for something whose
    future position is progressively less certain.

    `steps` is a fidelity knob, not a correctness one: more segments
    approximate the swept volume more closely from the outside, and one
    segment is still conservative because it is sized at the end of the
    window where the envelope is widest.

    `start_ms` and `end_ms` must be in the same timebase as
    `report.stamp`, which for a live deployment means wall-clock
    milliseconds. Mixing the two -- a report stamped on a monotonic clock
    and a window in wall-clock -- makes the report look billions of
    milliseconds stale, and the volume cap turns that into a refusal
    rather than a silently enormous reservation. That refusal is the
    intended behaviour, but the mismatch is worth avoiding on purpose.
    """
    if steps < 1 or steps > 64:
        raise FaspError("schema.invalid", "Occupancy sampling needs between 1 and 64 steps.")
    if end_ms <= start_ms:
        raise FaspError("schema.invalid", "An occupancy window must end after it begins.")

    guard_ms = report.stamp.half_width_ms + policy.decision_margin_s * 1000.0
    span = (end_ms - start_ms) / steps
    segments = []
    for index in range(steps):
        step_start = int(start_ms + index * span)
        step_end = int(start_ms + (index + 1) * span) if index < steps - 1 else int(end_ms)
        if step_end <= step_start:
            continue
        # Size each slice at its own end, where the envelope is widest
        # within that slice. Sizing at the start would under-reserve by
        # exactly the growth across the slice.
        envelope = envelope_for(report, policy, step_end, morphology=morphology, body_radius_m=body_radius_m)
        segments.append(segment_from_envelope(envelope, start_ms=step_start, end_ms=step_end, cell=cell, guard_ms=guard_ms))
    if not segments:
        raise FaspError("schema.invalid", "The occupancy window is too short to produce a segment.")
    return segments


def reserve_occupancy(
    book: Any,
    owner: str,
    report: StateReport,
    policy: GuardPolicy,
    *,
    morphology: Morphology,
    cell: str,
    start_ms: int,
    end_ms: int,
    body_radius_m: float = 0.0,
    steps: int = 4,
    lease_ms: int = 30_000,
    reservation_id: str | None = None,
) -> dict[str, Any]:
    """Ask `book` for the space this report implies the robot will occupy.

    A convenience over `ReservationBook.request`, kept thin on purpose:
    it composes the two halves and adds nothing, so there is no second
    place where the geometry could be computed differently.
    """
    payload: dict[str, Any] = {
        "segments": segments_for_occupancy(
            report,
            policy,
            morphology=morphology,
            cell=cell,
            start_ms=start_ms,
            end_ms=end_ms,
            body_radius_m=body_radius_m,
            steps=steps,
        ),
        "lease_ms": lease_ms,
    }
    if reservation_id is not None:
        payload["reservation_id"] = reservation_id
    return book.request(owner, payload)
