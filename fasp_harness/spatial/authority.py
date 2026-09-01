"""Delegated authority: who may act on whom, where, and until when.

The question this answers is the one the whole air-ground problem keeps
arriving at: when a drone has seen a route the ground robot cannot, may it
*tell* the ground robot to take it?

Not as master and slave. Neither platform is permanently in charge --
whichever one currently has the better view of the problem holds authority
over a bounded piece of it, for a bounded time, and then stops. A
`SpatialDelegation` is that piece: a named capability over a named
subject, confined to a volume in a named frame, with an expiry.

Four properties, each present because of a specific way distributed
authority goes wrong:

**It expires on its own.** The failure mode this exists for is the link
dropping while a delegation is outstanding. There is no revocation message
to lose, because expiry needs no message: after `not_after_ms` the
delegation is simply not valid, on both sides, whether or not they can
still hear each other. Split-brain requires two parties who each believe
they still hold authority, and a clock is enough to prevent that where a
network is not.

**It is bounded in space, and the bound covers the guard band.** A
delegation authorises acting somewhere the *entire* uncertainty envelope
fits, not merely where the reported position sits. Authorising on the
point estimate authorises exactly the case where the robot turned out to
be a metre from where it said -- which is the case the envelope was
computed for.

**It can never reach Layer 1.** Capabilities naming a safety function are
refused at construction, using the same deny list `fasp_harness/layers.py`
applies to adapters. There is no delegation, however well signed and
however urgent, that clears an e-stop or mutes a protective field. A drone
may propose a route; the ground robot's own safety layer remains the only
thing that decides whether wheels turn.

**It is symmetric.** `holder` and `subject` are names, not roles. The
drone holding authority over the ground robot and the ground robot holding
authority over the drone are the same construct with the fields swapped,
and the tests assert both directions, because a design that only works one
way is a master/slave design wearing different words.

Delegations are carried in the `constraints` field of the existing FASP
grant (`core.issue_grant`), not in a parallel credential system. The
signature, expiry, revocation and audit trail already built for grants
apply unchanged; this module supplies the spatial predicate that the
generic machinery has no way to express.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from ..layers import LayerGuard
from ..protocol.errors import FaspError
from ..robotics import MAX_LEASE_MS
from .guard import Envelope, Morphology
from .linalg import Vector

__all__ = ["Volume", "SpatialDelegation", "Authorisation", "MAX_DELEGATION_MS"]

# The same bound a space-time reservation gets in `fasp_harness/robotics.py`.
# Deliberately shared: two different maximum lease lengths in one system is
# a question an operator should never have to ask.
MAX_DELEGATION_MS = MAX_LEASE_MS


@dataclass(frozen=True)
class Volume:
    """An axis-aligned box in a named frame.

    A box rather than a polygon because the frame it is expressed in is
    itself uncertain, and the extra fidelity of a polygon boundary is
    smaller than the error in where that boundary actually is. When frame
    links get good enough for the difference to matter, this is the type
    to extend.
    """

    frame_id: str
    minimum_m: Vector
    maximum_m: Vector

    def __post_init__(self) -> None:
        if not self.frame_id:
            raise FaspError("schema.invalid", "A volume must name the frame it is expressed in.")
        if len(self.minimum_m) != 3 or len(self.maximum_m) != 3:
            raise FaspError("schema.invalid", "A volume needs three-dimensional bounds.")
        if not all(math.isfinite(value) for value in list(self.minimum_m) + list(self.maximum_m)):
            raise FaspError("schema.invalid", "Volume bounds must be finite.")
        if any(low >= high for low, high in zip(self.minimum_m, self.maximum_m, strict=True)):
            raise FaspError("schema.invalid", "Every volume axis must have positive extent.")

    def contains_point(self, point: Vector) -> bool:
        return all(low <= value <= high for value, low, high in zip(point, self.minimum_m, self.maximum_m, strict=True))

    def contains_box(self, center: Vector, half_extents_m: Vector) -> bool:
        """Whether the whole guard band fits, not merely its centre.

        This is the distinction the module exists to enforce: authorising
        on a point authorises exactly the case where the robot turned out
        not to be at that point.

        Takes the band per axis rather than as one radius, because that is
        the shape it actually has. A ground vehicle's band is wide in plan
        and thin vertically, and collapsing it to its worst axis would
        demand vertical headroom in the delegated volume that nothing
        physically needs.
        """
        if len(half_extents_m) != 3 or any(extent < 0.0 for extent in half_extents_m):
            raise FaspError("schema.invalid", "Half-extents must be three non-negative values.")
        return all(
            low <= value - extent and value + extent <= high
            for value, extent, low, high in zip(center, half_extents_m, self.minimum_m, self.maximum_m, strict=True)
        )

    def clearance_m(self, center: Vector, half_extents_m: Vector) -> float:
        """Signed slack: how much the band could grow and still fit.

        Negative when it already does not, by the amount it protrudes on
        its worst axis. Returned so a refusal can say how far outside the
        delegation the request was, rather than only that it was.
        """
        if len(half_extents_m) != 3 or any(extent < 0.0 for extent in half_extents_m):
            raise FaspError("schema.invalid", "Half-extents must be three non-negative values.")
        return min(
            min(value - extent - low, high - value - extent)
            for value, extent, low, high in zip(center, half_extents_m, self.minimum_m, self.maximum_m, strict=True)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"frame_id": self.frame_id, "minimum_m": list(self.minimum_m), "maximum_m": list(self.maximum_m)}

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> Volume:
        try:
            return cls(str(payload["frame_id"]), [float(value) for value in payload["minimum_m"]], [float(value) for value in payload["maximum_m"]])
        except (KeyError, TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "Volume payload is malformed.") from error


@dataclass(frozen=True)
class Authorisation:
    """Whether an action is permitted, and why not when it is not."""

    permitted: bool
    reason: str
    clearance_m: float
    remaining_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {"permitted": self.permitted, "reason": self.reason, "clearance_m": self.clearance_m, "remaining_ms": self.remaining_ms}


@dataclass(frozen=True)
class SpatialDelegation:
    """Bounded authority one system holds over another, in space and time."""

    holder: str
    subject: str
    capability: str
    volume: Volume
    not_before_ms: float
    not_after_ms: float
    max_speed_mps: float
    morphologies: frozenset[Morphology]

    def __post_init__(self) -> None:
        if not self.holder or not self.subject:
            raise FaspError("schema.invalid", "A delegation needs both a holder and a subject.")
        if self.holder == self.subject:
            raise FaspError("schema.invalid", "A system does not delegate authority to itself.")
        if not self.capability:
            raise FaspError("schema.invalid", "A delegation needs a capability.")
        # The same deny list adapters are validated against. No delegation,
        # however well signed, reaches a Layer 1 safety function.
        reason = LayerGuard.reserved_reason(self.capability)
        if reason is not None:
            raise FaspError(
                "policy.layer_violation",
                f"{self.capability!r} names a Layer 1 safety function. {reason} It cannot be delegated over the network at any scope or duration.",
            )
        if not math.isfinite(self.not_before_ms) or not math.isfinite(self.not_after_ms):
            raise FaspError("schema.invalid", "Delegation validity bounds must be finite.")
        if self.not_after_ms <= self.not_before_ms:
            raise FaspError("schema.invalid", "A delegation must expire after it begins.")
        if self.not_after_ms - self.not_before_ms > MAX_DELEGATION_MS:
            raise FaspError("schema.invalid", f"A delegation may not run longer than {MAX_DELEGATION_MS} ms.")
        if self.max_speed_mps <= 0.0 or not math.isfinite(self.max_speed_mps):
            raise FaspError("schema.invalid", "A delegation must cap speed at a finite positive value.")
        if not self.morphologies:
            raise FaspError("schema.invalid", "A delegation must name at least one morphology it applies to.")

    def remaining_ms(self, now_ms: float) -> float:
        return max(0.0, self.not_after_ms - now_ms)

    def valid_at(self, now_ms: float) -> bool:
        return self.not_before_ms <= now_ms < self.not_after_ms

    def authorise(self, envelope: Envelope, now_ms: float, *, requested_speed_mps: float | None = None) -> Authorisation:
        """Whether `envelope` may be acted on under this delegation now.

        Ordered so the cheapest and most absolute refusals come first, and
        so the reason returned is the most fundamental one rather than
        whichever check happened to run last.
        """
        remaining = self.remaining_ms(now_ms)
        clearance = float("-inf")

        if now_ms < self.not_before_ms:
            return Authorisation(False, "the delegation has not begun", clearance, remaining)
        if now_ms >= self.not_after_ms:
            # No revocation message was needed, and none could have been lost.
            return Authorisation(False, "the delegation has expired", clearance, 0.0)
        if envelope.robot_id != self.subject:
            return Authorisation(False, f"this delegation covers {self.subject!r}, not {envelope.robot_id!r}", clearance, remaining)
        if envelope.frame_id != self.volume.frame_id:
            return Authorisation(
                False,
                f"the envelope is in frame {envelope.frame_id!r} and the delegation bounds frame {self.volume.frame_id!r}",
                clearance,
                remaining,
            )
        if envelope.morphology not in self.morphologies:
            return Authorisation(False, f"this delegation does not cover {envelope.morphology.value} platforms", clearance, remaining)
        if requested_speed_mps is not None and requested_speed_mps > self.max_speed_mps:
            return Authorisation(
                False,
                f"requested {requested_speed_mps:.3f} m/s exceeds the delegated cap of {self.max_speed_mps:.3f} m/s",
                clearance,
                remaining,
            )

        clearance = self.volume.clearance_m(envelope.center_m, envelope.half_extents_m)
        if clearance < 0.0:
            extents = " x ".join(f"{extent:.3f}" for extent in envelope.half_extents_m)
            return Authorisation(
                False,
                f"the {extents} m uncertainty envelope protrudes {-clearance:.3f} m outside the delegated volume",
                clearance,
                remaining,
            )
        return Authorisation(True, f"within the delegated volume with {clearance:.3f} m to spare and {remaining:.0f} ms remaining", clearance, remaining)

    def to_constraints(self) -> dict[str, Any]:
        """The `constraints` payload for `FaspHarness.issue_grant`.

        Carried inside the existing grant rather than as a parallel
        credential, so the signature, revocation and audit trail already
        built for grants cover this unchanged.
        """
        return {
            "spatial_delegation": {
                "holder": self.holder,
                "subject": self.subject,
                "capability": self.capability,
                "volume": self.volume.to_dict(),
                "not_before_ms": self.not_before_ms,
                "not_after_ms": self.not_after_ms,
                "max_speed_mps": self.max_speed_mps,
                "morphologies": sorted(item.value for item in self.morphologies),
            }
        }

    @classmethod
    def from_constraints(cls, constraints: dict[str, Any]) -> SpatialDelegation:
        payload = (constraints or {}).get("spatial_delegation")
        if not isinstance(payload, dict):
            raise FaspError("schema.invalid", "Grant constraints carry no spatial delegation.")
        try:
            morphologies = frozenset(Morphology(value) for value in payload["morphologies"])
        except (KeyError, TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "Spatial delegation names an unknown morphology.") from error
        try:
            return cls(
                holder=str(payload["holder"]),
                subject=str(payload["subject"]),
                capability=str(payload["capability"]),
                volume=Volume.from_mapping(payload["volume"]),
                not_before_ms=float(payload["not_before_ms"]),
                not_after_ms=float(payload["not_after_ms"]),
                max_speed_mps=float(payload["max_speed_mps"]),
                morphologies=morphologies,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "Spatial delegation payload is malformed.") from error
