"""Guard bands: turning uncertainty into a decision about separation.

Everything upstream produces numbers. This is where they become an answer
to the only question that matters operationally -- *may these two machines
proceed* -- and it answers it with a stated risk rather than an implied
certainty.

A guard band is the clear space around a robot's predicted position. It is
an **axis-aligned box, not a sphere**, and that is not a detail. A sphere
has one radius, so it must be sized by the worst axis of the covariance --
which for a ground vehicle, confident vertically and uncertain in plan,
means a band reaching metres below the floor it is driving on. Every
consumer then has to be told to ignore the vertical, and a bound nobody
believes is a bound nobody keeps.

The box is tight rather than merely convenient. The k-sigma ellipsoid
`{x : x' P^-1 x <= k^2}` has support `k * sqrt(P_ii)` in axis `i`, so the
box with those half-extents is its exact axis-aligned bound. It is smaller
than the enclosing sphere in every axis and equal in the worst one, so
nothing is given up by using it.

Each half-extent is computed two ways, and the larger wins:

    statistical   k * sqrt(P_ii propagated to now)
                  Believes the motion model. Tight, and correct while the
                  robot is doing what it said it would.

    reachable     k * sqrt(P_ii at the report) + v_max_i * horizon
                  Believes only the speed limit. Covers the case the
                  statistical bound cannot see at all: the peer received a
                  new command we never heard, and is no longer following
                  the trajectory it last told us about.

`v_max_i` is per-axis and comes from the motion model, because the model
is what knows the medium. A wheeled robot's vertical reach is set by the
steepest ramp it could be on, not by its ground speed -- treating
reachability as isotropic makes a 2 m/s AMR look able to climb at 2 m/s,
which is what put the old spherical band through the floor.

They are taken as a maximum, never a sum. Adding them double-counts the
motion since the report -- once through the propagated covariance and
again through `v_max * horizon` -- which inflates the band for no reason
and trains operators to disable it. For short delays the statistical bound
is tighter and is used; as the delay grows the reachable bound takes over,
which is the correct crossover: the longer the silence, the less the model
is evidence of anything.

`horizon` is deliberately not just the message age. It is age plus the
time still to come before the decision can take effect -- one control
period, plus the communication margin. A band sized for the delay already
suffered, ignoring the delay still ahead, is late by exactly the amount
that matters.

The coverage factor `k` comes from the chi-square quantile at the stated
risk `alpha` for the relevant number of dimensions. For a planar check at
alpha = 1e-6 that is the familiar `sqrt(-2 ln alpha)`, about 5.26. In three
dimensions the same risk needs about 5.54, and using the planar figure for
a volumetric problem quietly buys a worse guarantee than the one written
down -- so the dimension is a parameter, not an assumption.

Separation between two boxes is the separating-axis test, which is exact:
they are apart if and only if some axis separates them. That the test
names *which* axis is not decoration -- "cleared by 18.6 m of altitude" and
"cleared by 0.2 m laterally" are different operational situations, and a
verdict that reports only a scalar margin cannot tell them apart.

Morphology is the cross-domain piece. Conflict is a predicate over *pairs*
of morphologies, not a universal overlap test: an aerial robot and a
subsurface one are separated by the water column no matter what their
horizontal coordinates say, and testing them against each other wastes
work and invents conflicts. Pairs that genuinely can meet -- air with
ground during landing, surface with subsurface beneath a hull -- fall
through to the ordinary geometric test, which handles altitude on its own.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..protocol.errors import FaspError
from .state import StateReport

__all__ = [
    "Morphology",
    "GuardPolicy",
    "Envelope",
    "Separation",
    "coverage_factor",
    "envelope_for",
    "check_separation",
    "MORPHOLOGY_INTERACTS",
    "AXIS_NAMES",
]

AXIS_NAMES = ("east", "north", "up")


class Morphology(Enum):
    """Where a platform lives. Determines which pairs can ever meet."""

    AIR = "air"
    SURFACE = "surface"
    GROUND = "ground"
    SUBSURFACE = "subsurface"


# Which pairs require a separation check at all. The False entries are not
# optimisations -- they are statements that the medium itself separates the
# pair, and testing them would manufacture conflicts between machines that
# cannot reach each other.
MORPHOLOGY_INTERACTS: dict[frozenset[Morphology], bool] = {
    frozenset({Morphology.AIR}): True,
    frozenset({Morphology.GROUND}): True,
    frozenset({Morphology.SURFACE}): True,
    frozenset({Morphology.SUBSURFACE}): True,
    # Landing, take-off, and low-altitude transit over a working floor.
    frozenset({Morphology.AIR, Morphology.GROUND}): True,
    # Landing on a vessel or a moving deck.
    frozenset({Morphology.AIR, Morphology.SURFACE}): True,
    # Ramps, slipways, docks: the shoreline is shared.
    frozenset({Morphology.GROUND, Morphology.SURFACE}): True,
    # A hull and the submersible beneath it share a volume.
    frozenset({Morphology.SURFACE, Morphology.SUBSURFACE}): True,
    # The water column separates these regardless of coordinates.
    frozenset({Morphology.AIR, Morphology.SUBSURFACE}): False,
    frozenset({Morphology.GROUND, Morphology.SUBSURFACE}): False,
}


def _chi_square_survival(k: float, dimensions: int) -> float:
    """P(chi distributed radius exceeds k) for 1, 2 or 3 dimensions."""
    if dimensions == 1:
        return math.erfc(k / math.sqrt(2.0))
    if dimensions == 2:
        return math.exp(-k * k / 2.0)
    if dimensions == 3:
        return math.erfc(k / math.sqrt(2.0)) + math.sqrt(2.0 / math.pi) * k * math.exp(-k * k / 2.0)
    raise FaspError("schema.invalid", "Coverage factors are defined here for one, two or three dimensions.")


def coverage_factor(alpha: float, dimensions: int = 2) -> float:
    """How many sigma bound the position at residual risk `alpha`.

    In two dimensions this has the closed form `sqrt(-2 ln alpha)`; in one
    and three it is inverted numerically by bisection on the survival
    function, which is monotone, so bisection is both simple and certain
    to converge.

    The point of returning a number derived from a stated `alpha` -- rather
    than a hard-coded "three sigma" -- is that the risk becomes an input a
    safety case can quote and an operator can argue about, instead of a
    constant nobody can trace.
    """
    if not 0.0 < alpha < 1.0:
        raise FaspError("schema.invalid", "Residual risk must lie strictly between zero and one.")
    if dimensions == 2:
        return math.sqrt(-2.0 * math.log(alpha))
    low, high = 0.0, 1.0
    while _chi_square_survival(high, dimensions) > alpha:
        high *= 2.0
        if high > 1e6:
            raise FaspError("schema.invalid", "Residual risk is too small to resolve.")
    for _ in range(200):
        middle = (low + high) / 2.0
        if _chi_square_survival(middle, dimensions) > alpha:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


@dataclass(frozen=True)
class GuardPolicy:
    """The stated risk appetite and timing margins of a deployment.

    `latency_margin_s` and `control_period_s` exist because a band sized
    for the delay already suffered, while ignoring the delay still ahead,
    is late by exactly the amount that matters. Size them from the p99 of
    the measured round trip, not the mean: queueing on a shared radio is
    heavy-tailed, and the mean describes a link nobody experiences.
    """

    risk_alpha: float = 1e-6
    dimensions: int = 3
    latency_margin_s: float = 0.2
    control_period_s: float = 0.1

    def __post_init__(self) -> None:
        if self.latency_margin_s < 0.0 or self.control_period_s < 0.0:
            raise FaspError("schema.invalid", "Timing margins cannot be negative.")
        # Validates alpha and dimensions by construction.
        coverage_factor(self.risk_alpha, self.dimensions)

    @property
    def coverage_k(self) -> float:
        return coverage_factor(self.risk_alpha, self.dimensions)

    @property
    def decision_margin_s(self) -> float:
        return self.latency_margin_s + self.control_period_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_alpha": self.risk_alpha,
            "dimensions": self.dimensions,
            "latency_margin_s": self.latency_margin_s,
            "control_period_s": self.control_period_s,
            "coverage_k": self.coverage_k,
        }


@dataclass(frozen=True)
class Envelope:
    """An axis-aligned box that must stay clear, and the reasoning behind it."""

    robot_id: str
    frame_id: str
    morphology: Morphology
    center_m: list[float]
    half_extents_m: list[float]
    basis: str
    statistical_half_extents_m: list[float]
    reachable_half_extents_m: list[float]
    body_radius_m: float
    horizon_s: float
    risk_alpha: float
    beyond_model: bool

    def __post_init__(self) -> None:
        if len(self.center_m) != 3 or len(self.half_extents_m) != 3:
            raise FaspError("schema.invalid", "An envelope is three-dimensional.")
        if any(extent < 0.0 or not math.isfinite(extent) for extent in self.half_extents_m):
            raise FaspError("schema.invalid", "Envelope half-extents must be finite and non-negative.")

    @property
    def radius_m(self) -> float:
        """The enclosing sphere, for reporting and for scalar comparisons.

        Kept as a derived value rather than the primary one: it is the
        number to put in a summary line, never the number to make a
        decision with, because it is the worst axis applied to all three.
        """
        return max(self.half_extents_m)

    def minimum_m(self) -> list[float]:
        return [value - extent for value, extent in zip(self.center_m, self.half_extents_m, strict=True)]

    def maximum_m(self) -> list[float]:
        return [value + extent for value, extent in zip(self.center_m, self.half_extents_m, strict=True)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "robot_id": self.robot_id,
            "frame_id": self.frame_id,
            "morphology": self.morphology.value,
            "center_m": list(self.center_m),
            "half_extents_m": list(self.half_extents_m),
            "radius_m": self.radius_m,
            "basis": self.basis,
            "statistical_half_extents_m": list(self.statistical_half_extents_m),
            "reachable_half_extents_m": list(self.reachable_half_extents_m),
            "body_radius_m": self.body_radius_m,
            "horizon_s": self.horizon_s,
            "risk_alpha": self.risk_alpha,
            "beyond_model": self.beyond_model,
        }


@dataclass(frozen=True)
class Separation:
    """The verdict, with every number that produced it.

    `clear` is the answer; the rest is the reason. A separation decision
    that cannot be explained after the fact is not usable evidence in a
    safety case, and this is the record an audit entry would carry.

    `separating_axis` names the axis that proves the pair apart, or is
    None when none does. "Cleared by 18.6 m of altitude" and "cleared by
    0.2 m laterally" are different operational situations, and a verdict
    reporting only a scalar cannot distinguish them.
    """

    clear: bool
    distance_m: float
    margin_m: float
    separating_axis: str | None
    axis_margins_m: list[float]
    reason: str
    first: Envelope
    second: Envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "clear": self.clear,
            "distance_m": self.distance_m,
            "margin_m": self.margin_m,
            "separating_axis": self.separating_axis,
            "axis_margins_m": list(self.axis_margins_m),
            "reason": self.reason,
            "first": self.first.to_dict(),
            "second": self.second.to_dict(),
        }


def envelope_for(
    report: StateReport,
    policy: GuardPolicy,
    now_ms: float,
    *,
    morphology: Morphology,
    body_radius_m: float = 0.0,
) -> Envelope:
    """Size the clear-space box around `report` as of `now_ms`.

    The centre is the propagated mean. Each half-extent is the larger of
    the two bounds described in the module docstring, plus the robot's own
    physical radius -- because a guard band around a point is a band around
    a point, and machines are not points.
    """
    if body_radius_m < 0.0 or not math.isfinite(body_radius_m):
        raise FaspError("schema.invalid", "Body radius must be finite and non-negative.")

    propagated = report.propagated_to(now_ms)
    horizon_s = report.age_s(now_ms) + policy.decision_margin_s
    coverage = policy.coverage_k
    # Reachability is per-axis and comes from the motion model, because
    # the model is what knows the medium. A ground vehicle cannot climb at
    # its ground speed, and pretending it can inflates its band vertically
    # by metres and conflicts it with aircraft it can never touch.
    reach_m = [rate * horizon_s for rate in report.motion.reach_mps(report.speed_limit_mps)]

    # k * sqrt(P_ii) is the exact support of the k-sigma ellipsoid along
    # axis i, so these half-extents bound it tightly rather than loosely.
    statistical = [coverage * math.sqrt(max(propagated.covariance[axis][axis], 0.0)) for axis in range(3)]
    # The reachable bound starts from the uncertainty at the *report*, not
    # the propagated one: the motion since is accounted for by the speed
    # limit term, and using the propagated sigma here would double-count it.
    reachable = [coverage * math.sqrt(max(report.covariance[axis][axis], 0.0)) + reach_m[axis] for axis in range(3)]

    half_extents = [max(a, b) + body_radius_m for a, b in zip(statistical, reachable, strict=True)]
    dominant = ["statistical" if a >= b else "reachable" for a, b in zip(statistical, reachable, strict=True)]
    basis = dominant[0] if len(set(dominant)) == 1 else "mixed"

    return Envelope(
        robot_id=report.robot_id,
        frame_id=propagated.frame_id,
        morphology=morphology,
        center_m=list(propagated.position_m),
        half_extents_m=half_extents,
        basis=basis,
        statistical_half_extents_m=statistical,
        reachable_half_extents_m=reachable,
        body_radius_m=body_radius_m,
        horizon_s=horizon_s,
        risk_alpha=policy.risk_alpha,
        beyond_model=report.beyond_model(now_ms),
    )


def check_separation(first: Envelope, second: Envelope) -> Separation:
    """Whether two envelopes are provably apart at their stated risk.

    The separating-axis test on two axis-aligned boxes, which is exact:
    they are apart if and only if some axis separates them, and the margin
    is the widest such gap.

    Refuses to compare envelopes expressed in different frames. That is
    not pedantry: two positions in different frames are two different
    claims about the world, and comparing them as though they were
    commensurable is the single most dangerous thing this package could
    silently do. Bring them into a common frame with
    `StateReport.in_frame()` first, which adds the frame link's own error
    to the comparison as it should.
    """
    if first.frame_id != second.frame_id:
        raise FaspError(
            "schema.invalid",
            f"Cannot compare separation across frames {first.frame_id} and {second.frame_id}; express both in one frame first.",
        )
    if first.robot_id == second.robot_id:
        raise FaspError("schema.invalid", "A robot does not need separation from itself.")

    distance = math.sqrt(math.fsum((a - b) ** 2 for a, b in zip(first.center_m, second.center_m, strict=True)))
    axis_margins = [
        abs(a - b) - (extent_a + extent_b)
        for a, b, extent_a, extent_b in zip(first.center_m, second.center_m, first.half_extents_m, second.half_extents_m, strict=True)
    ]

    pair = frozenset({first.morphology, second.morphology})
    if not MORPHOLOGY_INTERACTS.get(pair, True):
        return Separation(
            clear=True,
            distance_m=distance,
            margin_m=distance,
            separating_axis="medium",
            axis_margins_m=axis_margins,
            reason=f"{first.morphology.value} and {second.morphology.value} are separated by the medium and cannot meet",
            first=first,
            second=second,
        )

    margin = max(axis_margins)
    index = axis_margins.index(margin)
    if margin > 0.0:
        axis = AXIS_NAMES[index]
        reason = f"separated by {margin:.3f} m along {axis} at residual risk {first.risk_alpha:g}"
        return Separation(True, distance, margin, axis, axis_margins, reason, first, second)

    overlaps = ", ".join(f"{AXIS_NAMES[axis]} {-value:.3f} m" for axis, value in enumerate(axis_margins))
    return Separation(
        clear=False,
        distance_m=distance,
        margin_m=margin,
        separating_axis=None,
        axis_margins_m=axis_margins,
        reason=f"no axis separates the pair; envelopes overlap on all three ({overlaps})",
        first=first,
        second=second,
    )
