"""The vendor-neutral vocabulary every fleet adapter maps into.

Two design decisions are worth stating, because both are load bearing.

**Missions are goals, not trajectories.** A `MissionStep` names a place and
an action -- go to node 12, pick load L, charge to 80% -- and never a path,
a velocity, or a wheel command. That is not minimalism; it is the layer
boundary. The moment a fleet coordinator sends a trajectory it has taken
responsibility for obstacle avoidance over a network link with no timing
guarantee. `StepKind` has no member that could express one.

**The vocabulary borrows VDA 5050's where it exists.** `OperatingMode`,
`ActionStatus`, and `ErrorLevel` use that standard's own values, so the
adapter for the most common real-world interface is a rename rather than a
lossy translation, and a site already running VDA 5050 sees terms its
integrators recognise.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from ..protocol.errors import FaspError
from ..timestamps import stamp


class StepKind(StrEnum):
    """Goal-level actions. Deliberately not extensible into motion control."""

    MOVE = "move"
    PICK = "pick"
    DROP = "drop"
    CHARGE = "charge"
    DOCK = "dock"
    UNDOCK = "undock"
    WAIT = "wait"
    CUSTOM = "custom"


class MissionState(StrEnum):
    ACCEPTED = "ACCEPTED"
    PREFLIGHT = "PREFLIGHT"
    ASSIGNED = "ASSIGNED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"

    @property
    def terminal(self) -> bool:
        return self in {MissionState.COMPLETED, MissionState.FAILED, MissionState.CANCELLED, MissionState.REJECTED}


class OperatingMode(StrEnum):
    """VDA 5050 5.x operating modes, reused verbatim."""

    AUTOMATIC = "AUTOMATIC"
    SEMIAUTOMATIC = "SEMIAUTOMATIC"
    MANUAL = "MANUAL"
    SERVICE = "SERVICE"
    TEACHIN = "TEACHIN"

    @property
    def accepts_missions(self) -> bool:
        """Only a fully automatic vehicle may be given work. A vehicle in
        MANUAL or TEACHIN has a human in control of it, and dispatching to
        one is how a coordinator surprises the person standing next to it."""
        return self is OperatingMode.AUTOMATIC


class ActionStatus(StrEnum):
    WAITING = "WAITING"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    FINISHED = "FINISHED"
    FAILED = "FAILED"


class ErrorLevel(StrEnum):
    WARNING = "WARNING"
    FATAL = "FATAL"


@dataclass(frozen=True)
class Pose:
    """A pose on a named map. `map_id` is mandatory: coordinates without a
    frame are the single most common integration bug in this domain."""

    x: float
    y: float
    theta: float = 0.0
    map_id: str = "default"

    def distance_to(self, other: Pose) -> float:
        if self.map_id != other.map_id:
            raise FaspError("schema.invalid", "Cannot measure a distance between poses on different maps.")
        return math.hypot(other.x - self.x, other.y - self.y)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> Pose:
        if not isinstance(value, dict):
            raise FaspError("schema.invalid", "A pose must be an object.")
        try:
            return cls(float(value["x"]), float(value["y"]), float(value.get("theta", 0.0)), str(value.get("map_id", "default")))
        except (KeyError, TypeError, ValueError) as exc:
            raise FaspError("schema.invalid", "A pose requires numeric x and y.") from exc


@dataclass(frozen=True)
class MissionStep:
    step_id: str
    kind: StepKind
    node_id: str | None = None
    pose: Pose | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    timeout_s: float = 300.0
    blocking: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "kind": self.kind.value,
            "node_id": self.node_id,
            "pose": self.pose.to_dict() if self.pose else None,
            "parameters": self.parameters,
            "timeout_s": self.timeout_s,
            "blocking": self.blocking,
        }

    @classmethod
    def from_dict(cls, value: Any) -> MissionStep:
        if not isinstance(value, dict):
            raise FaspError("schema.invalid", "A mission step must be an object.")
        try:
            kind = StepKind(str(value.get("kind", "move")).lower())
        except ValueError as exc:
            raise FaspError("schema.invalid", f"Unknown mission step kind {value.get('kind')!r}.") from exc
        node_id = value.get("node_id")
        pose = Pose.from_dict(value["pose"]) if isinstance(value.get("pose"), dict) else None
        if kind is StepKind.MOVE and node_id is None and pose is None:
            raise FaspError("schema.invalid", "A move step requires a node_id or a pose.")
        timeout = value.get("timeout_s", 300.0)
        return cls(
            step_id=str(value.get("step_id") or uuid.uuid4()),
            kind=kind,
            node_id=str(node_id) if node_id is not None else None,
            pose=pose,
            parameters=dict(value.get("parameters") or {}),
            timeout_s=float(timeout) if isinstance(timeout, (int, float)) and 0 < timeout <= 86_400 else 300.0,
            blocking=bool(value.get("blocking", True)),
        )


MAX_MISSION_STEPS = 256


@dataclass(frozen=True)
class Mission:
    """One unit of Layer 3 work."""

    mission_id: str
    requested_by: str
    steps: tuple[MissionStep, ...]
    priority: int = 0
    fleet: str | None = None
    vehicle_id: str | None = None
    deadline_at: str | None = None
    constraints: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=stamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "requested_by": self.requested_by,
            "steps": [step.to_dict() for step in self.steps],
            "priority": self.priority,
            "fleet": self.fleet,
            "vehicle_id": self.vehicle_id,
            "deadline_at": self.deadline_at,
            "constraints": self.constraints,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: Any, *, requested_by: str) -> Mission:
        if not isinstance(value, dict):
            raise FaspError("schema.invalid", "A mission must be an object.")
        raw_steps = value.get("steps")
        if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= MAX_MISSION_STEPS:
            raise FaspError("schema.invalid", f"A mission needs between 1 and {MAX_MISSION_STEPS} steps.")
        priority = value.get("priority", 0)
        return cls(
            mission_id=str(value.get("mission_id") or f"mission-{uuid.uuid4()}")[:128],
            requested_by=requested_by,
            steps=tuple(MissionStep.from_dict(step) for step in raw_steps),
            priority=int(priority) if isinstance(priority, int) and -100 <= priority <= 100 else 0,
            fleet=str(value["fleet"])[:64] if value.get("fleet") else None,
            vehicle_id=str(value["vehicle_id"])[:128] if value.get("vehicle_id") else None,
            deadline_at=str(value["deadline_at"]) if value.get("deadline_at") else None,
            constraints=dict(value.get("constraints") or {}),
        )

    @property
    def cells(self) -> tuple[str, ...]:
        """Named places this mission touches, for space-time reservation."""
        return tuple(step.node_id for step in self.steps if step.node_id)


@dataclass(frozen=True)
class VehicleCapabilities:
    max_speed_mps: float = 1.5
    payload_kg: float = 0.0
    footprint_m: tuple[float, float] = (1.0, 0.6)
    supported_steps: tuple[StepKind, ...] = (StepKind.MOVE,)
    charge_types: tuple[str, ...] = ()
    vendor: str = "unknown"
    model: str = "unknown"
    interface: str = "unknown"

    def supports(self, mission: Mission) -> tuple[bool, str]:
        for step in mission.steps:
            if step.kind not in self.supported_steps:
                return False, f"Vehicle does not support the {step.kind.value!r} step."
        return True, "Vehicle supports every step in this mission."

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "supported_steps": [step.value for step in self.supported_steps], "footprint_m": list(self.footprint_m)}


@dataclass(frozen=True)
class VehicleState:
    """A normalised snapshot of one vehicle, from any vendor."""

    vehicle_id: str
    fleet: str
    online: bool
    operating_mode: OperatingMode
    pose: Pose | None
    battery_ratio: float
    charging: bool
    driving: bool
    paused: bool
    errors: tuple[dict[str, Any], ...] = ()
    current_mission_id: str | None = None
    velocity_mps: float = 0.0
    safety_estop_active: bool = False
    protective_field_violated: bool = False
    last_seen: str = field(default_factory=stamp)
    vendor_state: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def fatal_errors(self) -> tuple[dict[str, Any], ...]:
        return tuple(error for error in self.errors if str(error.get("level", "")).upper() == ErrorLevel.FATAL.value)

    def dispatchable(self, *, minimum_battery: float = 0.15) -> tuple[bool, str]:
        """Whether Layer 3 may hand this vehicle work right now.

        Every clause is a refusal a real deployment needs: dispatching to an
        offline vehicle silently queues work forever; dispatching to one in
        MANUAL surprises whoever is driving it; dispatching to one with an
        active E-stop produces an order it cannot start and a fault report
        nobody expected.
        """
        if not self.online:
            return False, "Vehicle is offline."
        if not self.operating_mode.accepts_missions:
            return False, f"Vehicle is in {self.operating_mode.value} mode, not AUTOMATIC."
        if self.safety_estop_active:
            return False, "Vehicle reports an active emergency stop."
        if self.protective_field_violated:
            return False, "Vehicle reports a violated protective field."
        if self.fatal_errors:
            return False, f"Vehicle reports {len(self.fatal_errors)} fatal error(s)."
        if self.current_mission_id:
            return False, f"Vehicle is already running mission {self.current_mission_id}."
        if self.battery_ratio < minimum_battery:
            return False, f"Battery at {self.battery_ratio:.0%} is below the {minimum_battery:.0%} dispatch floor."
        return True, "Vehicle is available."

    def to_dict(self) -> dict[str, Any]:
        return {
            "vehicle_id": self.vehicle_id,
            "fleet": self.fleet,
            "online": self.online,
            "operating_mode": self.operating_mode.value,
            "pose": self.pose.to_dict() if self.pose else None,
            "battery_ratio": round(self.battery_ratio, 4),
            "charging": self.charging,
            "driving": self.driving,
            "paused": self.paused,
            "errors": list(self.errors),
            "current_mission_id": self.current_mission_id,
            "velocity_mps": round(self.velocity_mps, 4),
            "safety_estop_active": self.safety_estop_active,
            "protective_field_violated": self.protective_field_violated,
            "last_seen": self.last_seen,
        }
