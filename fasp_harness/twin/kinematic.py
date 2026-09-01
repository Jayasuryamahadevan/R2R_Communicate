"""A deterministic site and vehicle model: the twin's physics.

Kept simple on purpose. The point of this model is not fidelity -- a real
deployment plugs in the vendor's own simulator, or Gazebo, or Isaac, behind
the same interface. The point is that the *integration* is real: a mission
is simulated before it is dispatched, and reality is compared against the
prediction afterwards. A model with three parameters that is genuinely
consulted beats a photorealistic one that is not.

Determinism is a hard requirement, not a nicety. Fixed timestep integration
with no wall-clock reads and no RNG means the same mission always yields
the same prediction, which is what makes a divergence attributable to the
*vehicle* rather than to the twin having had a different afternoon.

The model is trapezoidal-velocity along straight segments between nodes:
accelerate to cruise, hold, decelerate to a stop at the node. That
reproduces the dominant term in real AGV travel time -- accelerating and
stopping at every waypoint -- which is exactly the term a constant-speed
estimate gets most wrong on short hops.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from ..fleet.model import Pose
from ..protocol.errors import FaspError


@dataclass(frozen=True)
class DifferentialDriveModel:
    """Motion limits. `turn_rate_rps` makes a turn cost time, as it does."""

    max_speed_mps: float = 1.2
    acceleration_mps2: float = 0.5
    deceleration_mps2: float = 0.7
    turn_rate_rps: float = 0.8
    radius_m: float = 0.45
    idle_power_w: float = 40.0
    moving_power_w: float = 180.0
    battery_wh: float = 500.0

    def segment_time_s(self, distance_m: float) -> float:
        """Trapezoidal profile, degrading to triangular on a short hop."""
        if distance_m <= 0:
            return 0.0
        accelerate_distance = self.max_speed_mps**2 / (2 * self.acceleration_mps2)
        decelerate_distance = self.max_speed_mps**2 / (2 * self.deceleration_mps2)
        if accelerate_distance + decelerate_distance <= distance_m:
            cruise = distance_m - accelerate_distance - decelerate_distance
            return self.max_speed_mps / self.acceleration_mps2 + cruise / self.max_speed_mps + self.max_speed_mps / self.deceleration_mps2
        # Never reaches cruise speed: solve for the peak it does reach.
        peak = math.sqrt(2 * distance_m * self.acceleration_mps2 * self.deceleration_mps2 / (self.acceleration_mps2 + self.deceleration_mps2))
        return peak / self.acceleration_mps2 + peak / self.deceleration_mps2

    def turn_time_s(self, from_theta: float, to_theta: float) -> float:
        delta = abs((to_theta - from_theta + math.pi) % (2 * math.pi) - math.pi)
        return delta / self.turn_rate_rps if self.turn_rate_rps > 0 else 0.0

    def energy_wh(self, moving_s: float, idle_s: float = 0.0) -> float:
        return (self.moving_power_w * moving_s + self.idle_power_w * idle_s) / 3600.0


class OccupancyGrid:
    """A binary static map: blocked cells and a resolution.

    Deliberately not a costmap. Layer 2 owns inflation, clearance, and
    dynamic obstacles; the twin only needs to know whether a planned route
    crosses something that is definitely there, which is the class of
    mistake worth catching before a robot is sent.
    """

    def __init__(self, *, resolution_m: float = 0.5, blocked: set[tuple[int, int]] | None = None, map_id: str = "default") -> None:
        if resolution_m <= 0:
            raise FaspError("schema.invalid", "Grid resolution must be positive.")
        self.resolution_m = resolution_m
        self.map_id = map_id
        self.blocked = set(blocked or ())

    def cell(self, x: float, y: float) -> tuple[int, int]:
        return (math.floor(x / self.resolution_m), math.floor(y / self.resolution_m))

    def block_rectangle(self, x0: float, y0: float, x1: float, y1: float) -> None:
        low_x, high_x = sorted((x0, x1))
        low_y, high_y = sorted((y0, y1))
        for column in range(math.floor(low_x / self.resolution_m), math.floor(high_x / self.resolution_m) + 1):
            for row in range(math.floor(low_y / self.resolution_m), math.floor(high_y / self.resolution_m) + 1):
                self.blocked.add((column, row))

    def is_blocked(self, x: float, y: float) -> bool:
        return self.cell(x, y) in self.blocked

    def trace(self, start: Pose, end: Pose, *, step_m: float | None = None) -> list[tuple[int, int]]:
        """Cells a straight segment passes through, sampled at half a cell.

        Half-resolution sampling rather than a Bresenham line: it is the
        conservative choice, and over-reporting a cell costs a false
        preflight rejection while under-reporting one costs a collision.
        """
        step = step_m or self.resolution_m / 2.0
        distance = math.hypot(end.x - start.x, end.y - start.y)
        samples = max(1, int(distance / step))
        cells: list[tuple[int, int]] = []
        for index in range(samples + 1):
            fraction = index / samples
            cell = self.cell(start.x + (end.x - start.x) * fraction, start.y + (end.y - start.y) * fraction)
            if not cells or cells[-1] != cell:
                cells.append(cell)
        return cells

    def blocked_on(self, start: Pose, end: Pose) -> list[tuple[int, int]]:
        return [cell for cell in self.trace(start, end) if cell in self.blocked]

    def to_dict(self) -> dict[str, Any]:
        return {"map_id": self.map_id, "resolution_m": self.resolution_m, "blocked_cells": len(self.blocked)}


@dataclass
class SiteModel:
    """Named nodes, the static map, and the vehicles modelled on it."""

    nodes: dict[str, Pose] = field(default_factory=dict)
    grid: OccupancyGrid = field(default_factory=OccupancyGrid)
    vehicles: dict[str, DifferentialDriveModel] = field(default_factory=dict)

    def pose_of(self, node_id: str) -> Pose:
        pose = self.nodes.get(node_id)
        if pose is None:
            raise FaspError("schema.invalid", f"Unknown map node {node_id!r}.")
        return pose

    def model_for(self, vehicle_id: str) -> DifferentialDriveModel:
        return self.vehicles.get(vehicle_id, DifferentialDriveModel())

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": sorted(self.nodes), "grid": self.grid.to_dict(), "vehicles": sorted(self.vehicles)}


@dataclass
class VehicleSim:
    """One vehicle's simulated state, advanced by a fixed timestep."""

    vehicle_id: str
    pose: Pose
    model: DifferentialDriveModel = field(default_factory=DifferentialDriveModel)
    battery_ratio: float = 1.0
    elapsed_s: float = 0.0
    distance_m: float = 0.0
    speed_mps: float = 0.0

    def travel_to(self, target: Pose, *, timestep_s: float = 0.1) -> dict[str, Any]:
        """Advance to `target` along a straight line, in fixed steps.

        Returns the trace, so a caller can check every intermediate pose
        against the map rather than only the endpoints -- the difference
        between "the destination is clear" and "the route is clear".
        """
        turn_s = self.model.turn_time_s(self.pose.theta, math.atan2(target.y - self.pose.y, target.x - self.pose.x) if (target.x, target.y) != (self.pose.x, self.pose.y) else self.pose.theta)
        distance = self.pose.distance_to(target)
        travel_s = self.model.segment_time_s(distance)
        trace: list[Pose] = []
        steps = max(1, int(travel_s / timestep_s))
        for index in range(1, steps + 1):
            fraction = index / steps
            trace.append(Pose(self.pose.x + (target.x - self.pose.x) * fraction, self.pose.y + (target.y - self.pose.y) * fraction, target.theta, target.map_id))
        consumed_wh = self.model.energy_wh(travel_s + turn_s)
        self.battery_ratio = max(0.0, self.battery_ratio - consumed_wh / self.model.battery_wh)
        self.pose = target
        self.elapsed_s += travel_s + turn_s
        self.distance_m += distance
        self.speed_mps = 0.0
        return {"duration_s": travel_s + turn_s, "distance_m": distance, "energy_wh": consumed_wh, "trace": trace}

    def wait(self, duration_s: float) -> dict[str, Any]:
        consumed_wh = self.model.energy_wh(0.0, duration_s)
        self.battery_ratio = max(0.0, self.battery_ratio - consumed_wh / self.model.battery_wh)
        self.elapsed_s += duration_s
        return {"duration_s": duration_s, "distance_m": 0.0, "energy_wh": consumed_wh, "trace": []}

    def charge(self, target_ratio: float, rate_per_s: float = 0.002) -> dict[str, Any]:
        deficit = max(0.0, min(1.0, target_ratio) - self.battery_ratio)
        duration = deficit / rate_per_s if rate_per_s > 0 else 0.0
        self.battery_ratio = min(1.0, max(self.battery_ratio, target_ratio))
        self.elapsed_s += duration
        return {"duration_s": duration, "distance_m": 0.0, "energy_wh": 0.0, "trace": []}

    def to_dict(self) -> dict[str, Any]:
        return {
            "vehicle_id": self.vehicle_id,
            "pose": self.pose.to_dict(),
            "battery_ratio": round(self.battery_ratio, 4),
            "elapsed_s": round(self.elapsed_s, 3),
            "distance_m": round(self.distance_m, 3),
        }
