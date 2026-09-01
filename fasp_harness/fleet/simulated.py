"""A deterministic in-memory fleet, for tests, CI, and the offline bench.

Every property that makes this useful comes from it being *deterministic*:
`advance()` moves simulated time by an explicit amount, nothing runs on a
background thread, and identical inputs produce identical outputs. A fleet
test that depends on wall-clock timing is a flaky test, and a flaky test in
a safety-adjacent repository is worse than no test.

It is a test double and says so in `describe()`, so a deployment report can
never present simulated vehicles as real ones.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..protocol.errors import FaspError
from ..timestamps import stamp
from .model import Mission, MissionState, OperatingMode, Pose, StepKind, VehicleCapabilities, VehicleState


@dataclass
class SimulatedVehicle:
    vehicle_id: str
    pose: Pose = field(default_factory=lambda: Pose(0.0, 0.0))
    battery_ratio: float = 1.0
    speed_mps: float = 1.0
    operating_mode: OperatingMode = OperatingMode.AUTOMATIC
    online: bool = True
    estop_active: bool = False
    field_violated: bool = False
    paused: bool = False
    errors: list[dict[str, Any]] = field(default_factory=list)
    capabilities: VehicleCapabilities = field(
        default_factory=lambda: VehicleCapabilities(
            supported_steps=(StepKind.MOVE, StepKind.PICK, StepKind.DROP, StepKind.CHARGE, StepKind.WAIT, StepKind.DOCK, StepKind.UNDOCK),
            vendor="fasp-harness",
            model="simulated-amr",
            interface="in-process",
        )
    )
    mission: Mission | None = None
    step_index: int = 0
    step_elapsed_s: float = 0.0
    mission_state: MissionState = MissionState.COMPLETED
    travelled_m: float = 0.0


class SimulatedFleetManager:
    """A `FleetManagerAdapter` over an explicitly-advanced simulation."""

    def __init__(self, fleet: str = "sim", *, nodes: dict[str, Pose] | None = None, battery_drain_per_m: float = 0.0005) -> None:
        self.fleet = fleet
        self.nodes = dict(nodes or {})
        self.battery_drain_per_m = battery_drain_per_m
        self._lock = threading.RLock()
        self._vehicles: dict[str, SimulatedVehicle] = {}
        self._missions: dict[str, tuple[str, MissionState]] = {}
        self._stop_requests: list[dict[str, Any]] = []
        self.elapsed_s = 0.0

    # -- construction ------------------------------------------------------
    def add_vehicle(self, vehicle_id: str, **kwargs: Any) -> SimulatedVehicle:
        with self._lock:
            vehicle = SimulatedVehicle(vehicle_id=vehicle_id, **kwargs)
            self._vehicles[vehicle_id] = vehicle
            return vehicle

    def vehicle(self, vehicle_id: str) -> SimulatedVehicle:
        with self._lock:
            vehicle = self._vehicles.get(vehicle_id)
        if vehicle is None:
            raise FaspError("capability.unavailable", f"Unknown simulated vehicle {vehicle_id!r}.")
        return vehicle

    def node_pose(self, node_id: str) -> Pose:
        pose = self.nodes.get(node_id)
        if pose is None:
            raise FaspError("schema.invalid", f"Unknown map node {node_id!r}.")
        return pose

    # -- simulation ---------------------------------------------------------
    def advance(self, seconds: float) -> None:
        """Move every vehicle forward by `seconds` of simulated time."""
        with self._lock:
            self.elapsed_s += seconds
            for vehicle in self._vehicles.values():
                self._advance_vehicle(vehicle, seconds)

    def _advance_vehicle(self, vehicle: SimulatedVehicle, seconds: float) -> None:
        if vehicle.mission is None or vehicle.mission_state not in {MissionState.ASSIGNED, MissionState.RUNNING}:
            return
        if vehicle.paused or vehicle.estop_active or vehicle.field_violated or not vehicle.online:
            # A halted vehicle makes no progress. It also does not fail:
            # the mission stays where it is until the halt is resolved,
            # because a fleet coordinator turning a stop into a failure is
            # how a stopped robot ends up with a cancelled order and a
            # confused operator.
            return
        vehicle.mission_state = MissionState.RUNNING
        remaining = seconds
        # `vehicle.mission` is re-checked every iteration, not captured once:
        # `_finish_step` clears it the moment the last step completes, and a
        # loop that held a stale reference would keep advancing a mission
        # that had already ended.
        while remaining > 0 and vehicle.mission is not None and vehicle.step_index < len(vehicle.mission.steps):
            step = vehicle.mission.steps[vehicle.step_index]
            if step.kind is StepKind.MOVE:
                target = step.pose or self.node_pose(step.node_id or "")
                distance = vehicle.pose.distance_to(target)
                reach_s = distance / vehicle.speed_mps if vehicle.speed_mps > 0 else float("inf")
                if reach_s <= remaining:
                    vehicle.pose = target
                    vehicle.travelled_m += distance
                    vehicle.battery_ratio = max(0.0, vehicle.battery_ratio - distance * self.battery_drain_per_m)
                    remaining -= reach_s
                    self._finish_step(vehicle)
                    continue
                fraction = (remaining * vehicle.speed_mps) / distance if distance > 0 else 1.0
                vehicle.pose = Pose(
                    vehicle.pose.x + (target.x - vehicle.pose.x) * fraction,
                    vehicle.pose.y + (target.y - vehicle.pose.y) * fraction,
                    target.theta,
                    target.map_id,
                )
                vehicle.travelled_m += remaining * vehicle.speed_mps
                vehicle.battery_ratio = max(0.0, vehicle.battery_ratio - remaining * vehicle.speed_mps * self.battery_drain_per_m)
                return
            duration = float(step.parameters.get("duration_s", 1.0))
            if step.kind is StepKind.CHARGE:
                target_ratio = float(step.parameters.get("target_ratio", 0.8))
                rate = float(step.parameters.get("rate_per_s", 0.02))
                vehicle.battery_ratio = min(target_ratio, vehicle.battery_ratio + rate * remaining)
                duration = 0.0 if vehicle.battery_ratio >= target_ratio else float("inf")
            vehicle.step_elapsed_s += remaining
            if vehicle.step_elapsed_s >= duration:
                remaining = vehicle.step_elapsed_s - duration
                self._finish_step(vehicle)
                continue
            return
        if vehicle.mission is not None and vehicle.step_index >= len(vehicle.mission.steps):
            self._complete(vehicle)

    def _finish_step(self, vehicle: SimulatedVehicle) -> None:
        vehicle.step_index += 1
        vehicle.step_elapsed_s = 0.0
        if vehicle.mission is not None and vehicle.step_index >= len(vehicle.mission.steps):
            self._complete(vehicle)

    def _complete(self, vehicle: SimulatedVehicle) -> None:
        if vehicle.mission is not None:
            self._missions[vehicle.mission.mission_id] = (vehicle.vehicle_id, MissionState.COMPLETED)
        vehicle.mission_state = MissionState.COMPLETED
        vehicle.mission = None
        vehicle.step_index = 0

    # -- adapter interface ---------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "vendor_interface": "simulated",
            "real_hardware": False,
            "note": "Deterministic in-process simulation. Carries no safety integrity and represents no physical vehicle.",
            "vehicles": len(self._vehicles),
            "simulated_elapsed_s": round(self.elapsed_s, 3),
        }

    def _state_of(self, vehicle: SimulatedVehicle) -> VehicleState:
        return VehicleState(
            vehicle_id=vehicle.vehicle_id,
            fleet=self.fleet,
            online=vehicle.online,
            operating_mode=vehicle.operating_mode,
            pose=vehicle.pose,
            battery_ratio=vehicle.battery_ratio,
            charging=vehicle.mission is not None and vehicle.mission.steps[min(vehicle.step_index, len(vehicle.mission.steps) - 1)].kind is StepKind.CHARGE,
            driving=vehicle.mission_state is MissionState.RUNNING and not vehicle.paused,
            paused=vehicle.paused,
            errors=tuple(vehicle.errors),
            current_mission_id=vehicle.mission.mission_id if vehicle.mission else None,
            velocity_mps=vehicle.speed_mps if vehicle.mission_state is MissionState.RUNNING and not vehicle.paused else 0.0,
            safety_estop_active=vehicle.estop_active,
            protective_field_violated=vehicle.field_violated,
            last_seen=stamp(),
        )

    def list_vehicles(self) -> list[VehicleState]:
        with self._lock:
            return [self._state_of(vehicle) for vehicle in sorted(self._vehicles.values(), key=lambda item: item.vehicle_id)]

    def vehicle_state(self, vehicle_id: str) -> VehicleState:
        return self._state_of(self.vehicle(vehicle_id))

    def capabilities(self, vehicle_id: str) -> VehicleCapabilities:
        return self.vehicle(vehicle_id).capabilities

    def dispatch(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        vehicle = self.vehicle(vehicle_id)
        with self._lock:
            if vehicle.mission is not None:
                raise FaspError("resource.exhausted", f"Vehicle {vehicle_id!r} is already running a mission.")
            for step in mission.steps:
                if step.kind is StepKind.MOVE and step.pose is None and step.node_id not in self.nodes:
                    raise FaspError("schema.invalid", f"Mission references unknown map node {step.node_id!r}.")
            vehicle.mission = mission
            vehicle.step_index = 0
            vehicle.step_elapsed_s = 0.0
            vehicle.mission_state = MissionState.ASSIGNED
            self._missions[mission.mission_id] = (vehicle_id, MissionState.ASSIGNED)
        return {"interface": "simulated", "vehicle": vehicle_id, "steps": len(mission.steps)}

    def cancel(self, mission_id: str) -> bool:
        with self._lock:
            entry = self._missions.get(mission_id)
            if entry is None:
                return False
            vehicle_id, state = entry
            if state.terminal:
                return False
            vehicle = self._vehicles.get(vehicle_id)
            if vehicle is not None and vehicle.mission is not None and vehicle.mission.mission_id == mission_id:
                vehicle.mission = None
                vehicle.step_index = 0
                vehicle.mission_state = MissionState.CANCELLED
            self._missions[mission_id] = (vehicle_id, MissionState.CANCELLED)
            return True

    def mission_state(self, mission_id: str) -> MissionState:
        with self._lock:
            entry = self._missions.get(mission_id)
            if entry is None:
                raise FaspError("capability.unavailable", f"Unknown mission {mission_id!r}.")
            vehicle_id, recorded = entry
            vehicle = self._vehicles.get(vehicle_id)
            if vehicle is not None and vehicle.mission is not None and vehicle.mission.mission_id == mission_id:
                return vehicle.mission_state
            return recorded

    def request_stop(self, vehicle_id: str, reason: str) -> bool:
        vehicle = self.vehicle(vehicle_id)
        with self._lock:
            vehicle.paused = True
            self._stop_requests.append({"vehicle": vehicle_id, "reason": str(reason)[:120], "at": stamp()})
        return True

    @property
    def stop_requests(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._stop_requests)
