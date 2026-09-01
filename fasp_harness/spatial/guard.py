"""Guard bands: turning uncertainty into a decision about separation.

Everything upstream produces numbers. This is where they become an answer
to the only question that matters operationally -- *may these two machines
proceed* -- and it answers it with a stated risk rather than an implied
certainty.

A guard band is the radius around a robot's predicted position that must
stay clear. It is computed two ways, and the larger wins:

    statistical   k * sigma(P propagated to now)
                  Believes the motion model. Tight, and correct while the
                  robot is doing what it said it would.

    reachable     k * sigma(P at the report) + v_max * horizon
                  Believes only the speed limit. Covers the case the
                  statistical bound cannot see at all: the peer received a
                  new command we never heard, and is no longer following
                  the trajectory it last told us about.

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

Morphology is the cross-domain piece. Conflict is a predicate over *pairs*
of morphologies, not a universal overlap test: an aerial robot and a
subsurface one are separated by the water column no matter what their
horizontal coordinates say, and testing them against each other wastes
work and invents conflicts. Pairs that genuinely can meet -- air with
ground during landing, surface with subsurface beneath a hull -- fall
through to the ordinary 3D test, which handles the altitude separation on
its own.
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
]


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
    """A sphere that must stay clear, and the reasoning that sized it."""

    robot_id: str
    frame_id: str
    morphology: Morphology
    center_m: list[float]
    radius_m: float
    basis: str
    statistical_radius_m: float
    reachable_radius_m: float
    body_radius_m: float
    horizon_s: float
    risk_alpha: float
    beyond_model: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "robot_id": self.robot_id,
            "frame_id": self.frame_id,
            "morphology": self.morphology.value,
            "center_m": list(self.center_m),
            "radius_m": self.radius_m,
            "basis": self.basis,
            "statistical_radius_m": self.statistical_radius_m,
            "reachable_radius_m": self.reachable_radius_m,
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
    """

    clear: bool
    distance_m: float
    required_m: float
    margin_m: float
    reason: str
    first: Envelope
    second: Envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "clear": self.clear,
            "distance_m": self.distance_m,
            "required_m": self.required_m,
            "margin_m": self.margin_m,
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
    """Size the clear-space sphere around `report` as of `now_ms`.

    The centre is the propagated mean. The radius is the larger of the two
    bounds described in the module docstring, plus the robot's own physical
    radius -- because a guard band around a point is a band around a point,
    and machines are not points.
    """
    if body_radius_m < 0.0 or not math.isfinite(body_radius_m):
        raise FaspError("schema.invalid", "Body radius must be finite and non-negative.")

    propagated = report.propagated_to(now_ms)
    horizon_s = report.age_s(now_ms) + policy.decision_margin_s
    coverage = policy.coverage_k

    statistical = coverage * propagated.position_sigma_m()
    # The reachable bound starts from the uncertainty at the *report*, not
    # the propagated one: the motion since is accounted for by the speed
    # limit term, and using the propagated sigma here would double-count it.
    reachable = coverage * report.position_sigma_m() + report.speed_limit_mps * horizon_s
    radius = max(statistical, reachable)

    return Envelope(
        robot_id=report.robot_id,
        frame_id=propagated.frame_id,
        morphology=morphology,
        center_m=list(propagated.position_m),
        radius_m=radius + body_radius_m,
        basis="statistical" if statistical >= reachable else "reachable",
        statistical_radius_m=statistical,
        reachable_radius_m=reachable,
        body_radius_m=body_radius_m,
        horizon_s=horizon_s,
        risk_alpha=policy.risk_alpha,
        beyond_model=report.beyond_model(now_ms),
    )


def check_separation(first: Envelope, second: Envelope) -> Separation:
    """Whether two envelopes are provably apart at their stated risk.

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
    required = first.radius_m + second.radius_m

    pair = frozenset({first.morphology, second.morphology})
    if not MORPHOLOGY_INTERACTS.get(pair, True):
        return Separation(
            clear=True,
            distance_m=distance,
            required_m=0.0,
            margin_m=distance,
            reason=f"{first.morphology.value} and {second.morphology.value} are separated by the medium and cannot meet",
            first=first,
            second=second,
        )

    margin = distance - required
    if margin > 0.0:
        reason = f"separated by {margin:.3f} m beyond the {required:.3f} m required at residual risk {first.risk_alpha:g}"
    else:
        reason = f"envelopes overlap by {-margin:.3f} m; {distance:.3f} m apart with {required:.3f} m required"
    return Separation(
        clear=margin > 0.0,
        distance_m=distance,
        required_m=required,
        margin_m=margin,
        reason=reason,
        first=first,
        second=second,
    )
