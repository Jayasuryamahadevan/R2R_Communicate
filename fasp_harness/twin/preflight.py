"""Simulate the mission before a robot is asked to do it.

This is the twin's load-bearing use. Every check here catches a class of
failure that otherwise gets discovered by a vehicle, in an aisle, in front
of somebody:

  unknown node        the mission names a place the site map does not have
  unsupported step    a tugger was sent a pick
  blocked route       the straight route crosses a known static obstacle
  insufficient energy the vehicle runs flat two thirds of the way
  deadline            the mission cannot finish in the time it was given
  space-time conflict the route crosses a cell already reserved to someone
                      else, at the same time

The last one is what makes preflight a *coordination* function rather than
a plausibility check: the predicted arrival times let the coordinator
compare a proposed mission against reservations that already exist, before
granting the ones this mission would need.

Everything returns reasons, not just a verdict. "Mission rejected" with no
explanation is the single most expensive message a fleet system emits,
because the next step is always someone reading logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..fleet.model import Mission, Pose, StepKind, VehicleCapabilities
from ..protocol.errors import FaspError
from .kinematic import SiteModel, VehicleSim


@dataclass
class PreflightResult:
    feasible: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    estimated_duration_s: float = 0.0
    distance_m: float = 0.0
    battery_after: float = 1.0
    battery_low_water: float = 1.0
    occupancy: list[dict[str, Any]] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feasible": self.feasible,
            "reasons": self.reasons,
            "warnings": self.warnings,
            "estimated_duration_s": round(self.estimated_duration_s, 3),
            "distance_m": round(self.distance_m, 3),
            "battery_after": round(self.battery_after, 4),
            "battery_low_water": round(self.battery_low_water, 4),
            "occupancy": self.occupancy,
            "steps": self.steps,
        }

    def raise_if_infeasible(self) -> None:
        if not self.feasible:
            raise FaspError("policy.preflight_failed", "; ".join(self.reasons[:3]) or "Mission failed twin preflight.")


def preflight_mission(
    mission: Mission,
    *,
    site: SiteModel,
    start_pose: Pose,
    vehicle_id: str = "vehicle",
    battery_ratio: float = 1.0,
    capabilities: VehicleCapabilities | None = None,
    reserve_battery: float = 0.10,
    deadline_s: float | None = None,
    occupied: list[dict[str, Any]] | None = None,
    now_ms: int = 0,
) -> PreflightResult:
    """Run `mission` through the twin and report whether it can be done.

    `occupied` is a list of `{"cell", "start_ms", "end_ms", "owner"}` -- the
    space-time reservations already granted to *other* vehicles. Predicted
    arrival windows are compared against them, so a conflict is found here
    rather than at the reservation call after the mission is already
    accepted.
    """
    result = PreflightResult(feasible=True)
    if capabilities is not None:
        supported, detail = capabilities.supports(mission)
        if not supported:
            result.feasible = False
            result.reasons.append(detail)

    simulation = VehicleSim(vehicle_id=vehicle_id, pose=start_pose, model=site.model_for(vehicle_id), battery_ratio=battery_ratio)
    low_water = battery_ratio
    cursor_ms = float(now_ms)

    for index, step in enumerate(mission.steps):
        record: dict[str, Any] = {"index": index, "step_id": step.step_id, "kind": step.kind.value}
        try:
            if step.kind in {StepKind.MOVE, StepKind.PICK, StepKind.DROP, StepKind.DOCK, StepKind.UNDOCK}:
                target = step.pose or (site.pose_of(step.node_id) if step.node_id else simulation.pose)
                if target.map_id != simulation.pose.map_id:
                    result.feasible = False
                    result.reasons.append(f"Step {index} moves between maps ({simulation.pose.map_id!r} -> {target.map_id!r}), which this coordinator cannot plan.")
                    break
                origin = simulation.pose
                blocked = site.grid.blocked_on(origin, target)
                outcome = simulation.travel_to(target)
                if blocked:
                    result.feasible = False
                    result.reasons.append(f"Step {index} ({step.kind.value} -> {step.node_id or 'pose'}) crosses {len(blocked)} known-blocked cell(s), first at {blocked[0]}.")
                cells = site.grid.trace(origin, target)
                entry_ms = cursor_ms
                cursor_ms += outcome["duration_s"] * 1000.0
                # A non-move step keeps the vehicle where it is for its
                # dwell, and the cell is occupied for that whole time. The
                # window therefore spans travel AND dwell -- a pick at the
                # node the vehicle is already standing on has zero travel
                # but is emphatically not a zero-length occupancy.
                if step.kind is not StepKind.MOVE:
                    dwell = float(step.parameters.get("duration_s", 10.0))
                    simulation.wait(dwell)
                    cursor_ms += dwell * 1000.0
                    record["dwell_s"] = dwell
                result.occupancy.extend({"cell": f"{cell[0]},{cell[1]}", "start_ms": int(entry_ms), "end_ms": int(cursor_ms)} for cell in cells)
                record.update(duration_s=round(outcome["duration_s"], 3), distance_m=round(outcome["distance_m"], 3), cells=len(cells))
            elif step.kind is StepKind.CHARGE:
                outcome = simulation.charge(float(step.parameters.get("target_ratio", 0.8)))
                cursor_ms += outcome["duration_s"] * 1000.0
                record.update(duration_s=round(outcome["duration_s"], 3), charged_to=round(simulation.battery_ratio, 4))
            else:
                dwell = float(step.parameters.get("duration_s", 5.0))
                simulation.wait(dwell)
                cursor_ms += dwell * 1000.0
                record["duration_s"] = dwell
        except FaspError as error:
            result.feasible = False
            result.reasons.append(f"Step {index}: {error.detail}")
            record["error"] = error.code
            result.steps.append(record)
            break

        low_water = min(low_water, simulation.battery_ratio)
        record["battery_after"] = round(simulation.battery_ratio, 4)
        result.steps.append(record)

    result.estimated_duration_s = simulation.elapsed_s
    result.distance_m = simulation.distance_m
    result.battery_after = simulation.battery_ratio
    result.battery_low_water = low_water

    if low_water < reserve_battery:
        result.feasible = False
        result.reasons.append(f"Battery would fall to {low_water:.0%}, below the {reserve_battery:.0%} reserve; add a charge step or pick another vehicle.")
    elif result.battery_after < reserve_battery * 2:
        result.warnings.append(f"Mission ends at {result.battery_after:.0%} battery, close to the {reserve_battery:.0%} reserve.")

    if deadline_s is not None and result.estimated_duration_s > deadline_s:
        result.feasible = False
        result.reasons.append(f"Predicted {result.estimated_duration_s:.0f}s exceeds the {deadline_s:.0f}s deadline.")

    # Merge per cell before anyone reserves it: a route that crosses one
    # cell in three consecutive steps should hold it once, for the union of
    # those windows, not three times. Also drops any window that rounded to
    # zero length, which no reservation system can act on.
    result.occupancy = _merge_windows(result.occupancy)

    conflicts = _space_time_conflicts(result.occupancy, occupied or [])
    if conflicts:
        result.feasible = False
        first = conflicts[0]
        result.reasons.append(f"Predicted route conflicts with {len(conflicts)} existing reservation(s); first at cell {first['cell']} held by {first['owner']}.")
        result.occupancy = result.occupancy[:64]
    else:
        # The occupancy list is evidence, not payload: keep a bounded window
        # so a long mission's preflight does not inflate every response and
        # audit record that carries it.
        result.occupancy = result.occupancy[:64]
    return result


def _merge_windows(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Union the windows for each cell, in first-visit order."""
    merged: dict[str, dict[str, Any]] = {}
    for window in windows:
        if window["end_ms"] <= window["start_ms"]:
            continue
        existing = merged.get(window["cell"])
        if existing is None:
            merged[window["cell"]] = dict(window)
        else:
            existing["start_ms"] = min(existing["start_ms"], window["start_ms"])
            existing["end_ms"] = max(existing["end_ms"], window["end_ms"])
    return list(merged.values())


def _space_time_conflicts(predicted: list[dict[str, Any]], occupied: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Overlap in both space and time. Same cell at different times is fine
    -- that is the entire point of reserving space-time rather than space."""
    by_cell: dict[str, list[dict[str, Any]]] = {}
    for reservation in occupied:
        cell = str(reservation.get("cell", ""))
        if cell:
            by_cell.setdefault(cell, []).append(reservation)
    conflicts: list[dict[str, Any]] = []
    for window in predicted:
        for reservation in by_cell.get(window["cell"], ()):
            start, end = int(reservation.get("start_ms", 0)), int(reservation.get("end_ms", 0))
            if window["start_ms"] < end and start < window["end_ms"]:
                conflicts.append({"cell": window["cell"], "owner": reservation.get("owner", "unknown"), "window": [window["start_ms"], window["end_ms"]], "held": [start, end]})
    return conflicts
