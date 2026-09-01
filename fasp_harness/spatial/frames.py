"""Frame alignment: the transform between two robots' ideas of "here".

A drone works in a local ENU frame anchored where it took off. A ground
robot works in a SLAM map frame with an arbitrary origin, an arbitrary
yaw, and drift. Nothing either of them says about position means anything
to the other until the rigid transform between those frames is known --
and that transform is *estimated*, never given.

Three properties of this module follow from that, and each exists because
its absence is a specific field failure:

**A frame link carries covariance, not just a transform.** A fit from four
noisy UWB ranges and a fit from a surveyed fiducial produce the same six
numbers and mean entirely different things. The 6x6 tangent-space
covariance is what tells them apart downstream, and `compose()` propagates
it through the adjoint so a two-hop chain is honestly less certain than
either hop.

**A frame link decays.** This is the one most often missed. A visual or
odometry-derived alignment was true when it was measured and is not true
now, because the SLAM frame it references drifts. `at()` inflates the
covariance by the link's declared drift rate times its age, so a link
measured ten minutes ago is automatically wide rather than quietly stale.
A surveyed link declares zero drift and does not decay, which is the whole
reason surveying is worth the trouble.

**Degenerate geometry is refused, not fitted.** Collinear correspondences
-- three markers in a row along a corridor wall, a robot that only ever
moved in a straight line -- leave rotation about that line completely
unconstrained. Kabsch still returns a rotation for such input. It is
meaningless, and `align_frames` raises instead of returning it.

Convention throughout: `transform` maps *source* frame coordinates into
*target* frame coordinates, `q = R p + t`. Tangent-space ordering is
translation first then rotation, matching the ordering used across ROS and
most SE(3) estimation literature, so the adjoint is

    Ad(T) = [[R, [t]x R],
             [0,       R]]
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..protocol.errors import FaspError
from .clock import TimeInterval
from .linalg import (
    Matrix,
    Vector,
    det3,
    identity,
    inverse,
    jacobi_eigh,
    mat_add,
    mat_scale,
    matmul,
    matvec,
    nearest_psd,
    outer,
    symmetrize,
    transpose,
)

__all__ = [
    "Rigid3",
    "DriftRate",
    "FrameLink",
    "FrameGraph",
    "align_frames",
    "skew",
    "DRIFT_BY_METHOD",
    "METHODS",
]

# How fast an alignment produced by each method stops being true, in metres
# and radians per second of age. These are deliberately conservative order
# -of-magnitude figures, not measurements of any particular robot: the
# point is that a caller who does not supply a drift rate gets a decaying
# link rather than an eternal one.
DRIFT_BY_METHOD: dict[str, tuple[float, float]] = {
    # Bolted to the building. Does not move, so it does not decay.
    "surveyed": (0.0, 0.0),
    # Both ends hold an independent absolute fix; the relative error is
    # bounded by receiver noise rather than growing.
    "gnss": (0.0, 0.0),
    # Ranging is re-measured continuously; ageing one reflects only the
    # motion that happened since, not unbounded estimator drift.
    "uwb": (0.01, 0.0005),
    # Anchored to a SLAM frame, which drifts. This is the decaying case.
    "visual": (0.05, 0.002),
    "odometry": (0.20, 0.010),
    # An operator typed it in. It was never measured, so it cannot be
    # re-measured, and it should be trusted least of all with age.
    "declared": (0.50, 0.020),
}
METHODS = frozenset(DRIFT_BY_METHOD)

# Below this ratio between the second and first eigenvalue of the source
# point scatter, the correspondences are effectively collinear and rotation
# about the common axis is unobservable.
COLLINEARITY_RATIO = 1e-6


def skew(vector: Vector) -> Matrix:
    """The matrix `[v]x` with `[v]x w == v cross w`."""
    x, y, z = vector
    return [[0.0, -z, y], [z, 0.0, -x], [-y, x, 0.0]]


def _is_rotation(matrix: Matrix, tolerance: float = 1e-6) -> bool:
    if len(matrix) != 3 or any(len(row) != 3 for row in matrix):
        return False
    product = matmul(transpose(matrix), matrix)
    orthonormal = all(abs(product[row][column] - (1.0 if row == column else 0.0)) <= tolerance for row in range(3) for column in range(3))
    return orthonormal and abs(det3(matrix) - 1.0) <= tolerance


@dataclass(frozen=True)
class Rigid3:
    """A rigid transform in SE(3): `q = R p + t`."""

    rotation: Matrix
    translation: Vector

    def __post_init__(self) -> None:
        if not _is_rotation(self.rotation):
            # Rejected rather than orthonormalised. A peer sending a matrix
            # that is not a rotation is either broken or probing, and
            # silently projecting it onto SO(3) would accept both.
            raise FaspError("schema.invalid", "Rigid transform requires a proper orthonormal rotation with determinant +1.")
        if len(self.translation) != 3 or not all(math.isfinite(value) for value in self.translation):
            raise FaspError("schema.invalid", "Rigid transform requires a finite three-element translation.")

    @classmethod
    def identity(cls) -> Rigid3:
        return cls(identity(3), [0.0, 0.0, 0.0])

    def apply(self, point: Vector) -> Vector:
        return [a + b for a, b in zip(matvec(self.rotation, point), self.translation, strict=True)]

    def inverse(self) -> Rigid3:
        rotation = transpose(self.rotation)
        return Rigid3(rotation, [-value for value in matvec(rotation, self.translation)])

    def compose(self, other: Rigid3) -> Rigid3:
        """`self . other` -- apply `other` first, then `self`."""
        return Rigid3(matmul(self.rotation, other.rotation), self.apply(other.translation))

    def adjoint(self) -> Matrix:
        """The 6x6 adjoint, for moving a covariance through this transform."""
        rotation, block = self.rotation, matmul(skew(self.translation), self.rotation)
        top = [list(rotation[row]) + list(block[row]) for row in range(3)]
        bottom = [[0.0, 0.0, 0.0] + list(rotation[row]) for row in range(3)]
        return top + bottom

    def translation_norm_m(self) -> float:
        return math.sqrt(math.fsum(value * value for value in self.translation))

    def rotation_angle_rad(self) -> float:
        """Geodesic angle of the rotation, from its trace."""
        cosine = (math.fsum(self.rotation[index][index] for index in range(3)) - 1.0) / 2.0
        return math.acos(max(-1.0, min(1.0, cosine)))

    def to_dict(self) -> dict[str, object]:
        return {"rotation": [list(row) for row in self.rotation], "translation": list(self.translation)}

    @classmethod
    def from_mapping(cls, payload: dict[str, object]) -> Rigid3:
        rotation, translation = payload.get("rotation"), payload.get("translation")
        if not isinstance(rotation, list) or len(rotation) != 3 or not isinstance(translation, list):
            raise FaspError("schema.invalid", "Rigid transform needs a 3x3 rotation and a 3-vector translation.")
        try:
            rows = [[float(value) for value in row] for row in rotation]
            offset = [float(value) for value in translation]
        except (TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "Rigid transform entries must be numbers.") from error
        return cls(rows, offset)


@dataclass(frozen=True)
class DriftRate:
    """How fast an alignment stops being true, per second of age."""

    translation_m_per_s: float = 0.0
    rotation_rad_per_s: float = 0.0

    def __post_init__(self) -> None:
        if self.translation_m_per_s < 0.0 or self.rotation_rad_per_s < 0.0:
            raise FaspError("schema.invalid", "Drift rates cannot be negative.")

    @classmethod
    def for_method(cls, method: str) -> DriftRate:
        translation, rotation = DRIFT_BY_METHOD.get(method, DRIFT_BY_METHOD["declared"])
        return cls(translation, rotation)

    def inflation(self, age_s: float) -> Matrix:
        """Diagonal covariance added for `age_s` seconds of staleness.

        Growth is quadratic in age because the drift rates are rates of
        *position* error, and a variance is the square of a position. A
        link twice as old is four times as uncertain.
        """
        age = max(age_s, 0.0)
        translation_variance = (self.translation_m_per_s * age) ** 2
        rotation_variance = (self.rotation_rad_per_s * age) ** 2
        diagonal = [translation_variance] * 3 + [rotation_variance] * 3
        return [[diagonal[row] if row == column else 0.0 for column in range(6)] for row in range(6)]

    def to_dict(self) -> dict[str, float]:
        return {"translation_m_per_s": self.translation_m_per_s, "rotation_rad_per_s": self.rotation_rad_per_s}


@dataclass(frozen=True)
class FrameLink:
    """An estimated transform between two named frames, with its error bars."""

    source_frame: str
    target_frame: str
    transform: Rigid3
    covariance: Matrix
    method: str
    observed_at: TimeInterval
    drift: DriftRate = field(default_factory=DriftRate)
    residual_rms_m: float = 0.0
    correspondences: int = 0

    def __post_init__(self) -> None:
        if not self.source_frame or not self.target_frame:
            raise FaspError("schema.invalid", "A frame link needs both frame names.")
        if self.source_frame == self.target_frame:
            raise FaspError("schema.invalid", "A frame link must join two different frames.")
        if len(self.covariance) != 6 or any(len(row) != 6 for row in self.covariance):
            raise FaspError("schema.invalid", "A frame link covariance must be 6x6.")
        values, _ = jacobi_eigh(symmetrize(self.covariance))
        scale = max(abs(values[0]), 1.0)
        if values[-1] < -1e-9 * scale:
            raise FaspError("schema.invalid", "A frame link covariance must be positive semidefinite.")

    def age_s(self, now_ms: float) -> float:
        """Seconds since the observation, measured from its latest bound.

        Taking the latest bound rather than the centre means clock
        uncertainty in the observation makes the link look *younger* than
        it might be, never older -- so age never over-inflates on the
        strength of a bad clock alone. The clock's own error reaches the
        result through `observed_at` elsewhere.
        """
        return max(0.0, (now_ms - self.observed_at.latest_ms) / 1000.0)

    def at(self, now_ms: float) -> FrameLink:
        """This link as it should be trusted *now*, inflated for its age."""
        age = self.age_s(now_ms)
        if age <= 0.0:
            return self
        inflated = mat_add(symmetrize(self.covariance), self.drift.inflation(age))
        return FrameLink(
            self.source_frame,
            self.target_frame,
            self.transform,
            inflated,
            self.method,
            self.observed_at,
            self.drift,
            self.residual_rms_m,
            self.correspondences,
        )

    def inverse(self) -> FrameLink:
        """The link read in the other direction, covariance moved with it."""
        inverted = self.transform.inverse()
        adjoint = inverted.adjoint()
        moved = matmul(matmul(adjoint, symmetrize(self.covariance)), transpose(adjoint))
        return FrameLink(
            self.target_frame,
            self.source_frame,
            inverted,
            nearest_psd(moved),
            self.method,
            self.observed_at,
            self.drift,
            self.residual_rms_m,
            self.correspondences,
        )

    def compose(self, other: FrameLink) -> FrameLink:
        """Chain `self` (a->b) with `other` (b->c) into a->c.

        Covariances add in the frame of the result, which is what the
        adjoint is for. Two independent hops are therefore strictly less
        certain than either alone -- the property that makes a long chain
        of frame links visibly untrustworthy instead of invisibly so.

        Independence is assumed and is the honest weak point: two links
        sharing a sensor are correlated, and this addition understates the
        result. The composed link records the *worst* method and drift of
        its inputs so the decay of the chain is governed by its weakest
        member.
        """
        if self.target_frame != other.source_frame:
            raise FaspError("schema.invalid", f"Cannot compose {self.source_frame}->{self.target_frame} with {other.source_frame}->{other.target_frame}.")
        adjoint = self.transform.adjoint()
        moved = matmul(matmul(adjoint, symmetrize(other.covariance)), transpose(adjoint))
        combined = nearest_psd(mat_add(symmetrize(self.covariance), moved))
        worst_drift = DriftRate(
            max(self.drift.translation_m_per_s, other.drift.translation_m_per_s),
            max(self.drift.rotation_rad_per_s, other.drift.rotation_rad_per_s),
        )
        earliest = self.observed_at if self.observed_at.latest_ms <= other.observed_at.latest_ms else other.observed_at
        return FrameLink(
            self.source_frame,
            other.target_frame,
            self.transform.compose(other.transform),
            combined,
            f"{self.method}+{other.method}",
            earliest,
            worst_drift,
            math.hypot(self.residual_rms_m, other.residual_rms_m),
            min(self.correspondences, other.correspondences) if self.correspondences and other.correspondences else 0,
        )

    def position_sigma_m(self) -> float:
        """Largest standard deviation of the translation block, in metres."""
        block = [row[:3] for row in self.covariance[:3]]
        values, _ = jacobi_eigh(symmetrize(block))
        return math.sqrt(max(values[0], 0.0)) if values else 0.0

    def rotation_sigma_rad(self) -> float:
        block = [row[3:] for row in self.covariance[3:]]
        values, _ = jacobi_eigh(symmetrize(block))
        return math.sqrt(max(values[0], 0.0)) if values else 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "source_frame": self.source_frame,
            "target_frame": self.target_frame,
            "transform": self.transform.to_dict(),
            "covariance": [list(row) for row in self.covariance],
            "method": self.method,
            "observed_at": self.observed_at.to_dict(),
            "drift": self.drift.to_dict(),
            "residual_rms_m": self.residual_rms_m,
            "correspondences": self.correspondences,
        }

    @classmethod
    def from_mapping(cls, payload: dict[str, object]) -> FrameLink:
        try:
            covariance = [[float(value) for value in row] for row in payload["covariance"]]  # type: ignore[union-attr]
            drift_payload = payload.get("drift") or {}
            drift = DriftRate(float(drift_payload.get("translation_m_per_s", 0.0)), float(drift_payload.get("rotation_rad_per_s", 0.0)))  # type: ignore[union-attr]
            return cls(
                str(payload["source_frame"]),
                str(payload["target_frame"]),
                Rigid3.from_mapping(payload["transform"]),  # type: ignore[arg-type]
                covariance,
                str(payload["method"]),
                TimeInterval.from_mapping(payload["observed_at"]),  # type: ignore[arg-type]
                drift,
                float(payload.get("residual_rms_m", 0.0)),  # type: ignore[arg-type]
                int(payload.get("correspondences", 0)),  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "Frame link payload is malformed.") from error


def align_frames(
    source_points: Sequence[Vector],
    target_points: Sequence[Vector],
    *,
    source_frame: str,
    target_frame: str,
    observed_at: TimeInterval,
    method: str = "uwb",
    drift: DriftRate | None = None,
    measurement_sigma_m: float | None = None,
) -> FrameLink:
    """Rigid alignment of two point sets by Kabsch, with a fitted covariance.

    Solves for the `R, t` minimising `sum |R p_i + t - q_i|^2` -- the
    classical Kabsch/Umeyama construction, with the determinant correction
    that keeps the answer a rotation instead of a reflection. Scale is
    fixed at 1: these are rigid bodies, and letting scale float would let
    a bad correspondence set be explained by shrinking the world.

    The covariance is a first-order propagation of the fit residual. The
    Jacobian of `R p` with respect to a small rotation is `-[R p]x`, so
    the rotation information is `sum [R p_i]x' [R p_i]x / sigma^2` and the
    translation information is `n / sigma^2` per axis. `sigma` comes from
    the residual unless the caller knows their sensor better and passes
    `measurement_sigma_m`.

    Raises when the geometry cannot support the fit: fewer than three
    correspondences, or points collinear enough that rotation about the
    common axis is unobservable.
    """
    if len(source_points) != len(target_points):
        raise FaspError("schema.invalid", "Frame alignment needs matching numbers of source and target points.")
    count = len(source_points)
    if count < 3:
        raise FaspError("schema.invalid", "Frame alignment needs at least three correspondences to fix a rotation.")
    if any(len(point) != 3 for point in source_points) or any(len(point) != 3 for point in target_points):
        raise FaspError("schema.invalid", "Frame alignment points must be three-dimensional.")
    if not all(math.isfinite(value) for point in list(source_points) + list(target_points) for value in point):
        raise FaspError("schema.invalid", "Frame alignment points must be finite.")

    source_centroid = [math.fsum(point[axis] for point in source_points) / count for axis in range(3)]
    target_centroid = [math.fsum(point[axis] for point in target_points) / count for axis in range(3)]
    centred_source = [[point[axis] - source_centroid[axis] for axis in range(3)] for point in source_points]
    centred_target = [[point[axis] - target_centroid[axis] for axis in range(3)] for point in target_points]

    scatter = [[0.0] * 3 for _ in range(3)]
    for point in centred_source:
        scatter = mat_add(scatter, outer(point, point))
    spread, _ = jacobi_eigh(symmetrize(scatter))
    if spread[0] <= 0.0 or spread[1] / spread[0] < COLLINEARITY_RATIO:
        raise FaspError(
            "schema.invalid",
            "Frame alignment correspondences are collinear or coincident; rotation about the common axis is unobservable.",
        )

    cross = [[0.0] * 3 for _ in range(3)]
    for source_point, target_point in zip(centred_source, centred_target, strict=True):
        cross = mat_add(cross, outer(source_point, target_point))

    left, _, right_transposed = _svd_for_alignment(cross)
    right = transpose(right_transposed)
    correction = identity(3)
    correction[2][2] = 1.0 if det3(matmul(right, transpose(left))) >= 0.0 else -1.0
    rotation = matmul(matmul(right, correction), transpose(left))
    translation = [target_centroid[axis] - value for axis, value in enumerate(matvec(rotation, source_centroid))]
    transform = Rigid3(rotation, translation)

    residuals = [[a - b for a, b in zip(transform.apply(source_point), target_point, strict=True)] for source_point, target_point in zip(source_points, target_points, strict=True)]
    squared = math.fsum(math.fsum(value * value for value in residual) for residual in residuals)
    degrees_of_freedom = max(3 * count - 6, 1)
    residual_rms = math.sqrt(squared / (3 * count))
    sigma = measurement_sigma_m if measurement_sigma_m is not None else math.sqrt(squared / degrees_of_freedom)
    # An exact fit is evidence of few points, not of a perfect sensor. Floor
    # sigma at a millimetre so three correspondences never yield a covariance
    # of zero and a guard band of nothing.
    sigma = max(sigma, 1e-3)

    variance = sigma * sigma
    translation_information = [[(count / variance) if row == column else 0.0 for column in range(3)] for row in range(3)]
    rotation_information = [[0.0] * 3 for _ in range(3)]
    for point in centred_source:
        rotated = matvec(rotation, point)
        cross_matrix = skew(rotated)
        rotation_information = mat_add(rotation_information, mat_scale(matmul(transpose(cross_matrix), cross_matrix), 1.0 / variance))

    covariance = [[0.0] * 6 for _ in range(6)]
    translation_covariance = inverse(translation_information)
    rotation_covariance = inverse(mat_add(rotation_information, mat_scale(identity(3), 1e-12)))
    for row in range(3):
        for column in range(3):
            covariance[row][column] = translation_covariance[row][column]
            covariance[row + 3][column + 3] = rotation_covariance[row][column]

    return FrameLink(
        source_frame=source_frame,
        target_frame=target_frame,
        transform=transform,
        covariance=nearest_psd(covariance),
        method=method,
        observed_at=observed_at,
        drift=drift if drift is not None else DriftRate.for_method(method),
        residual_rms_m=residual_rms,
        correspondences=count,
    )


def _svd_for_alignment(matrix: Matrix) -> tuple[Matrix, Vector, Matrix]:
    from .linalg import svd3

    return svd3(matrix)


class FrameGraph:
    """Named frames joined by links, with shortest-chain composition.

    The graph is what makes "where is the drone, in the ground robot's map"
    answerable without every pair of robots having measured each other
    directly. Paths are found breadth-first, so the answer is the chain
    with the fewest hops -- and because each hop adds covariance, fewest
    hops is also the most certain chain available, not merely the shortest.
    """

    def __init__(self) -> None:
        self._links: dict[tuple[str, str], FrameLink] = {}

    def add(self, link: FrameLink) -> None:
        """Register a link and its inverse, replacing any earlier estimate."""
        self._links[(link.source_frame, link.target_frame)] = link
        self._links[(link.target_frame, link.source_frame)] = link.inverse()

    def frames(self) -> set[str]:
        return {frame for pair in self._links for frame in pair}

    def has_direct(self, source_frame: str, target_frame: str) -> bool:
        return (source_frame, target_frame) in self._links

    def path(self, source_frame: str, target_frame: str) -> list[str] | None:
        if source_frame == target_frame:
            return [source_frame]
        seen = {source_frame}
        queue: deque[list[str]] = deque([[source_frame]])
        while queue:
            route = queue.popleft()
            for pair in self._links:
                if pair[0] != route[-1] or pair[1] in seen:
                    continue
                extended = route + [pair[1]]
                if pair[1] == target_frame:
                    return extended
                seen.add(pair[1])
                queue.append(extended)
        return None

    def lookup(self, source_frame: str, target_frame: str, *, now_ms: float | None = None) -> FrameLink:
        """The composed link from `source_frame` to `target_frame`.

        With `now_ms`, every hop is aged before composition, so a chain
        containing one stale link is wide even if the rest were measured a
        moment ago. That is the intended behaviour: a chain is only as
        current as its most neglected member.
        """
        route = self.path(source_frame, target_frame)
        if route is None:
            raise FaspError("capability.unavailable", f"No chain of frame links connects {source_frame} to {target_frame}.")
        if len(route) == 1:
            raise FaspError("schema.invalid", "A frame is trivially identical to itself; no link is needed.")
        composed: FrameLink | None = None
        for start, end in zip(route, route[1:], strict=False):
            hop = self._links[(start, end)]
            if now_ms is not None:
                hop = hop.at(now_ms)
            composed = hop if composed is None else composed.compose(hop)
        assert composed is not None
        return composed
