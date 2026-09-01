"""State reports: a pose that knows how wrong it is, and how fast it ages.

Nothing here acts on a received position. It acts on a *propagated*
position with a *grown* covariance, because by the time a report crosses a
radio link and is deserialised, the robot it describes has moved.

The propagation is the standard linear one, `x' = F x` and
`P' = F P F' + Q`, with one addition that is easy to omit and expensive to
omit:

    **Timing uncertainty becomes position uncertainty.** If the instant a
    measurement was taken is only known to within epsilon, and the robot
    was moving at v, then the position is uncertain by v*epsilon along the
    direction of travel -- regardless of how good the sensor was. That
    term is `outer(v, v) * epsilon^2` added to the position block, and it
    is the seam where `spatial/clock.py` meets this module. A system that
    propagates covariance perfectly but ignores it will report a
    confident, wrong position every time the clocks drift.

The process-noise models differ by domain, and the difference is not
cosmetic. A ground robot's uncertainty is strongly anisotropic: heading
error times distance travelled produces cross-track error that grows much
faster than along-track error, so a UGV that has driven ten metres is far
less certain about which side of the corridor it is on than about how far
down it has gone. A drone's is closer to isotropic and much larger,
because wind gusts dominate and they come from any direction. Modelling
both with one round blob is wrong in opposite directions.

Sign convention on time: a report stamped in the future is not
retrodicted. The mean is held still while the covariance still grows, so
a clock disagreement makes a peer look *less* certain rather than moving
it backwards along its own path.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Protocol

from ..protocol.errors import FaspError
from .clock import TimeInterval
from .frames import FrameLink
from .linalg import (
    Matrix,
    NotPositiveSemidefinite,
    Vector,
    cholesky,
    identity,
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
    "MotionModel",
    "ConstantVelocity",
    "GroundVehicle",
    "Aerial",
    "StateReport",
    "model_from_mapping",
    "TYPICAL_WIND_GUST_PSD",
    "TYPICAL_WHEEL_SLIP_PSD",
]

# Acceleration power spectral density, in m^2/s^3 -- the strength of the
# disturbance each platform cannot predict about itself. The gap between
# these two numbers is the whole reason a drone's prediction decays in
# under a second while a ground robot's stays usable for several.
TYPICAL_WIND_GUST_PSD = 2.0
TYPICAL_WHEEL_SLIP_PSD = 0.05

# Beyond this the linear model is not merely imprecise, it is describing a
# different situation than the one that produced the report. Propagation
# still works; `StateReport.beyond_model()` says when to stop believing it.
DEFAULT_MODEL_HORIZON_S = 10.0


class MotionModel(Protocol):
    """What a platform does between hearing from it and acting on it."""

    kind: str

    def transition(self, dt_s: float) -> Matrix: ...

    def process_noise(self, dt_s: float, velocity_mps: Vector) -> Matrix: ...

    def horizon_s(self) -> float: ...

    def to_dict(self) -> dict[str, Any]: ...


def _constant_velocity_transition(dt_s: float) -> Matrix:
    matrix = identity(6)
    for axis in range(3):
        matrix[axis][axis + 3] = dt_s
    return matrix


def _white_acceleration_noise(dt_s: float, psd_by_axis: Vector) -> Matrix:
    """Continuous white-noise acceleration, the standard tracking form.

        Q = q * [[dt^3/3, dt^2/2],
                 [dt^2/2, dt    ]]   per axis

    The position/velocity cross terms are not optional decoration: they
    encode that a robot which turns out to have been going faster than
    believed is also further along than believed. Dropping them
    understates position growth by roughly a factor of four.
    """
    dt = abs(dt_s)
    position_term = dt**3 / 3.0
    cross_term = dt**2 / 2.0
    noise = [[0.0] * 6 for _ in range(6)]
    for axis in range(3):
        psd = psd_by_axis[axis]
        noise[axis][axis] = psd * position_term
        noise[axis][axis + 3] = psd * cross_term
        noise[axis + 3][axis] = psd * cross_term
        noise[axis + 3][axis + 3] = psd * dt
    return noise


@dataclass(frozen=True)
class ConstantVelocity:
    """Isotropic constant-velocity motion. The neutral default."""

    kind: str = "constant_velocity"
    acceleration_psd: float = 0.5
    model_horizon_s: float = DEFAULT_MODEL_HORIZON_S

    def transition(self, dt_s: float) -> Matrix:
        return _constant_velocity_transition(dt_s)

    def process_noise(self, dt_s: float, velocity_mps: Vector) -> Matrix:
        return _white_acceleration_noise(dt_s, [self.acceleration_psd] * 3)

    def horizon_s(self) -> float:
        return self.model_horizon_s

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "acceleration_psd": self.acceleration_psd, "model_horizon_s": self.model_horizon_s}


@dataclass(frozen=True)
class GroundVehicle:
    """A wheeled robot on a surface: anisotropic, and mostly planar.

    Cross-track uncertainty grows faster than along-track because a
    heading error becomes a lateral offset in proportion to the distance
    driven. That is why a UGV ten metres down a corridor is much less sure
    which side of it it is on than how far along it has come, and why an
    isotropic model is wrong in both directions at once -- too pessimistic
    forwards, dangerously optimistic sideways.

    Vertical motion is not assumed to be zero, because ramps and lifts
    exist, but its noise is small.
    """

    kind: str = "ground_vehicle"
    along_track_psd: float = TYPICAL_WHEEL_SLIP_PSD
    heading_noise_rad_per_sqrt_s: float = 0.02
    vertical_psd: float = 0.001
    model_horizon_s: float = DEFAULT_MODEL_HORIZON_S

    def transition(self, dt_s: float) -> Matrix:
        return _constant_velocity_transition(dt_s)

    def process_noise(self, dt_s: float, velocity_mps: Vector) -> Matrix:
        dt = abs(dt_s)
        speed = math.sqrt(math.fsum(value * value for value in velocity_mps[:2]))
        # Heading error accumulates as a random walk; the lateral offset it
        # produces is that error times the distance driven in the interval.
        heading_sigma = self.heading_noise_rad_per_sqrt_s * math.sqrt(dt)
        cross_track_psd = self.along_track_psd + (speed * heading_sigma) ** 2 / max(dt, 1e-9)
        noise = _white_acceleration_noise(dt_s, [self.along_track_psd, self.along_track_psd, self.vertical_psd])
        if speed > 1e-6 and cross_track_psd > self.along_track_psd:
            # Rotate the extra cross-track term into world axes using the
            # direction of travel, so the growth is perpendicular to motion
            # rather than to whichever axis the map happens to use.
            forward = [velocity_mps[0] / speed, velocity_mps[1] / speed, 0.0]
            lateral = [-forward[1], forward[0], 0.0]
            extra = (cross_track_psd - self.along_track_psd) * abs(dt_s) ** 3 / 3.0
            lateral_block = mat_scale(outer(lateral, lateral), extra)
            for row in range(3):
                for column in range(3):
                    noise[row][column] += lateral_block[row][column]
        return noise

    def horizon_s(self) -> float:
        return self.model_horizon_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "along_track_psd": self.along_track_psd,
            "heading_noise_rad_per_sqrt_s": self.heading_noise_rad_per_sqrt_s,
            "vertical_psd": self.vertical_psd,
            "model_horizon_s": self.model_horizon_s,
        }


@dataclass(frozen=True)
class Aerial:
    """A rotorcraft: isotropic in the horizontal plane and far noisier.

    Wind gusts are the dominant unmodelled acceleration and they arrive
    from any bearing, so unlike a ground vehicle there is no favoured
    axis. The default PSD is roughly forty times the ground figure, which
    is why an aerial prediction is worth acting on for well under a second
    while a ground one survives several. Vertical noise is separated
    because a rotorcraft holds altitude with a different loop, usually
    better than it holds position.
    """

    kind: str = "aerial"
    gust_psd: float = TYPICAL_WIND_GUST_PSD
    vertical_psd: float = 0.5
    model_horizon_s: float = 3.0

    def transition(self, dt_s: float) -> Matrix:
        return _constant_velocity_transition(dt_s)

    def process_noise(self, dt_s: float, velocity_mps: Vector) -> Matrix:
        return _white_acceleration_noise(dt_s, [self.gust_psd, self.gust_psd, self.vertical_psd])

    def horizon_s(self) -> float:
        return self.model_horizon_s

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "gust_psd": self.gust_psd, "vertical_psd": self.vertical_psd, "model_horizon_s": self.model_horizon_s}


_MODEL_TYPES: dict[str, Any] = {"constant_velocity": ConstantVelocity, "ground_vehicle": GroundVehicle, "aerial": Aerial}


def model_from_mapping(payload: dict[str, Any]) -> MotionModel:
    kind = payload.get("kind")
    factory = _MODEL_TYPES.get(kind) if isinstance(kind, str) else None
    if factory is None:
        raise FaspError("schema.invalid", "Unknown motion model kind.")
    fields = {key: value for key, value in payload.items() if key != "kind"}
    try:
        return factory(**fields)
    except TypeError as error:
        raise FaspError("schema.invalid", "Motion model parameters are malformed.") from error


@dataclass(frozen=True)
class StateReport:
    """Where a robot was, how sure it was, and what it does next.

    The state vector is `[position(3); velocity(3)]` and the covariance is
    the matching 6x6. `speed_limit_mps` is separate from the reported
    velocity on purpose: it is what the platform *could* do, not what it
    was doing, and the guard band needs the former to bound where it might
    have got to.
    """

    robot_id: str
    frame_id: str
    position_m: Vector
    velocity_mps: Vector
    covariance: Matrix
    stamp: TimeInterval
    motion: MotionModel
    speed_limit_mps: float

    def __post_init__(self) -> None:
        if not self.robot_id or not self.frame_id:
            raise FaspError("schema.invalid", "A state report needs a robot id and a frame id.")
        if len(self.position_m) != 3 or len(self.velocity_mps) != 3:
            raise FaspError("schema.invalid", "Position and velocity must be three-dimensional.")
        if not all(math.isfinite(value) for value in list(self.position_m) + list(self.velocity_mps)):
            raise FaspError("schema.invalid", "Position and velocity must be finite.")
        if len(self.covariance) != 6 or any(len(row) != 6 for row in self.covariance):
            raise FaspError("schema.invalid", "A state report covariance must be 6x6.")
        if self.speed_limit_mps < 0.0 or not math.isfinite(self.speed_limit_mps):
            raise FaspError("schema.invalid", "A speed limit must be finite and non-negative.")
        # A peer can send any thirty-six floats. This is where one that is
        # not a covariance stops, before it is propagated into a guard band.
        try:
            cholesky(symmetrize(self.covariance), jitter=1e-12)
        except (NotPositiveSemidefinite, ValueError) as error:
            raise FaspError("schema.invalid", "A state report covariance must be symmetric positive definite.") from error
        if math.sqrt(math.fsum(value * value for value in self.velocity_mps)) > self.speed_limit_mps + 1e-9:
            raise FaspError("schema.invalid", "Reported velocity exceeds the reported speed limit.")

    @property
    def state(self) -> Vector:
        return list(self.position_m) + list(self.velocity_mps)

    def age_s(self, now_ms: float) -> float:
        return max(0.0, (now_ms - self.stamp.latest_ms) / 1000.0)

    def beyond_model(self, now_ms: float) -> bool:
        """True once the linear model is describing a different situation.

        Not an error and not a rejection -- the covariance keeps growing
        and the report stays usable. It is a signal that the *shape* of
        the uncertainty is no longer trustworthy, only its scale, which is
        what `spatial/guard.py` needs to know before it leans on a
        direction.
        """
        return self.age_s(now_ms) > self.motion.horizon_s()

    def position_sigma_m(self) -> float:
        block = [row[:3] for row in self.covariance[:3]]
        values, _ = jacobi_eigh(symmetrize(block))
        return math.sqrt(max(values[0], 0.0)) if values else 0.0

    def propagated_to(self, now_ms: float) -> StateReport:
        """This report as it should be believed at `now_ms`.

        Three sources of growth, all of them real:

        1. Process noise over the elapsed interval -- what the platform
           did that it could not tell us about.
        2. Timing uncertainty projected through velocity -- not knowing
           *when* is not knowing *where*, at v metres per second.
        3. The transition itself, which carries existing velocity
           uncertainty into position uncertainty.
        """
        dt_s = (now_ms - self.stamp.center_ms) / 1000.0
        # A report stamped in the future is a clock disagreement, not a
        # robot that has yet to move. Hold the mean, keep the growth.
        forward_dt_s = max(dt_s, 0.0)

        transition = self.motion.transition(forward_dt_s)
        mean = matvec(transition, self.state)
        propagated = matmul(matmul(transition, symmetrize(self.covariance)), transpose(transition))
        propagated = mat_add(propagated, self.motion.process_noise(dt_s, self.velocity_mps))

        timing_sigma_s = self.stamp.half_width_ms / 1000.0
        if timing_sigma_s > 0.0:
            # Not knowing when, at v metres per second, is not knowing
            # where -- along the direction of travel.
            smear = mat_scale(outer(self.velocity_mps, self.velocity_mps), timing_sigma_s**2)
            for row in range(3):
                for column in range(3):
                    propagated[row][column] += smear[row][column]

        return StateReport(
            robot_id=self.robot_id,
            frame_id=self.frame_id,
            position_m=mean[:3],
            velocity_mps=mean[3:],
            covariance=nearest_psd(propagated, floor=1e-12),
            stamp=TimeInterval(now_ms, self.stamp.half_width_ms),
            motion=self.motion,
            speed_limit_mps=self.speed_limit_mps,
        )

    def in_frame(self, link: FrameLink, *, now_ms: float | None = None) -> StateReport:
        """This report expressed in `link.target_frame`.

        Both uncertainties compose. A peer's position in *our* frame is
        uncertain by their measurement error *and* by how well we know the
        transform between us -- and in practice the second term dominates,
        which is why a robot with excellent onboard localisation can still
        be a poor coordination partner across a badly estimated frame
        boundary. Carrying only their covariance forward would hide
        exactly the error that matters.
        """
        if link.source_frame != self.frame_id:
            raise FaspError("schema.invalid", f"Cannot express a {self.frame_id} report through a {link.source_frame} link.")
        effective = link.at(now_ms) if now_ms is not None else link
        rotation = effective.transform.rotation
        position = effective.transform.apply(self.position_m)
        velocity = matvec(rotation, self.velocity_mps)

        # Rotate the reported covariance into the target frame.
        block = [[0.0] * 6 for _ in range(6)]
        for row in range(3):
            for column in range(3):
                block[row][column] = rotation[row][column]
                block[row + 3][column + 3] = rotation[row][column]
        rotated = matmul(matmul(block, symmetrize(self.covariance)), transpose(block))

        # Add the link's own error: translation directly, and rotation
        # through the lever arm to the point being transformed.
        link_translation = [row[:3] for row in effective.covariance[:3]]
        link_rotation = [row[3:] for row in effective.covariance[3:]]
        lever = matvec(rotation, self.position_m)
        lever_arm = [[0.0, -lever[2], lever[1]], [lever[2], 0.0, -lever[0]], [-lever[1], lever[0], 0.0]]
        rotation_contribution = matmul(matmul(lever_arm, link_rotation), transpose(lever_arm))
        for row in range(3):
            for column in range(3):
                rotated[row][column] += link_translation[row][column] + rotation_contribution[row][column]

        return StateReport(
            robot_id=self.robot_id,
            frame_id=effective.target_frame,
            position_m=position,
            velocity_mps=velocity,
            covariance=nearest_psd(rotated, floor=1e-12),
            stamp=self.stamp,
            motion=self.motion,
            speed_limit_mps=self.speed_limit_mps,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "robot_id": self.robot_id,
            "frame_id": self.frame_id,
            "position_m": list(self.position_m),
            "velocity_mps": list(self.velocity_mps),
            "covariance": [list(row) for row in self.covariance],
            "stamp": self.stamp.to_dict(),
            "motion": self.motion.to_dict(),
            "speed_limit_mps": self.speed_limit_mps,
        }

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> StateReport:
        try:
            return cls(
                robot_id=str(payload["robot_id"]),
                frame_id=str(payload["frame_id"]),
                position_m=[float(value) for value in payload["position_m"]],
                velocity_mps=[float(value) for value in payload["velocity_mps"]],
                covariance=[[float(value) for value in row] for row in payload["covariance"]],
                stamp=TimeInterval.from_mapping(payload["stamp"]),
                motion=model_from_mapping(payload["motion"]),
                speed_limit_mps=float(payload["speed_limit_mps"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FaspError("schema.invalid", "State report payload is malformed.") from error
