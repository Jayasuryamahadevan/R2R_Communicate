"""Layer 3, assembled: the path a mission actually takes.

Everything else in this repository is a component. This is the order they
run in, and the order is the design:

    1. record durably        before anything external happens, so a crash
                             mid-dispatch leaves a mission to reconcile
                             rather than a robot nobody is tracking
    2. safety gate           the supervisor's view of Layer 1. A latched
                             halt stops dispatch here, at the top, not in
                             seven places further down
    3. leadership            a fenced lease. A superseded coordinator is
                             refused at the moment of effect, not trusted
                             to have noticed it lost the election
    4. vehicle selection     across every vendor, with a reason recorded
                             for each rejection
    5. twin preflight        simulate before dispatching: reachable, in
                             battery, not through a wall, not in conflict
                             with somebody else's reservation
    6. space-time reservation  granted for the predicted route, atomically
    7. dispatch              goal-level, to the vendor adapter
    8. reconcile             poll vendor state, feed the twin, release
                             reservations, resolve terminal missions

Step 1 before step 7 is the property that matters most, and step 5 before
step 6 is what stops the fleet granting reservations for a mission that was
never going to work. If any step raises, the mission ends REJECTED or
FAILED with the reason attached -- there is no path that leaves a vehicle
holding work the coordinator has forgotten.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from ..audit.chain import AuditChain
from ..edge.lease import LeaderLease, LeaseLost
from ..protocol.errors import FaspError
from ..robotics import ReservationBook
from ..safety.interlock import SafetySupervisor
from ..storage.db import Database
from ..storage.missions_repo import MissionsRepo
from ..timestamps import stamp
from ..twin.kinematic import SiteModel
from ..twin.preflight import PreflightResult, preflight_mission
from ..twin.sync import TwinSync
from .adapter import FleetRegistry
from .model import Mission, MissionState, Pose

MAX_RESERVED_CELLS = 64


class MissionService:
    """Accept, validate, dispatch, and reconcile Layer 3 missions."""

    def __init__(
        self,
        db: Database,
        registry: FleetRegistry,
        *,
        audit: AuditChain | None = None,
        supervisor: SafetySupervisor | None = None,
        site: SiteModel | None = None,
        twin: TwinSync | None = None,
        reservations: ReservationBook | None = None,
        lease: LeaderLease | None = None,
        minimum_battery: float = 0.15,
        reserve_battery: float = 0.10,
    ) -> None:
        self.db = db
        self.registry = registry
        self.audit = audit
        self.supervisor = supervisor
        self.site = site
        self.twin = twin
        self.reservations = reservations
        self.lease = lease
        self.minimum_battery = minimum_battery
        self.reserve_battery = reserve_battery
        self.missions = MissionsRepo(db)
        self._lock = threading.RLock()
        self._reserved: dict[str, str] = {}

    # -- submission ---------------------------------------------------------
    def submit(self, mission: Mission) -> dict[str, Any]:
        """Run one mission through the whole pipeline. Never partially."""
        definition = mission.to_dict()
        if not self.missions.accept(mission.mission_id, mission.requested_by, definition, priority=mission.priority, fleet=mission.fleet, deadline_at=mission.deadline_at):
            # Idempotent resubmission: return the recorded outcome rather
            # than dispatching a second vehicle for the same request.
            existing = self.missions.get(mission.mission_id)
            return {"type": "mission.accepted", "duplicate": True, **self._render(existing)}

        self._audit("mission.accepted", mission.requested_by, {"mission_id": mission.mission_id, "steps": len(mission.steps)})
        try:
            return self._dispatch(mission)
        except FaspError as error:
            self.missions.finish(mission.mission_id, MissionState.REJECTED.value, error={"code": error.code, "detail": error.detail})
            self._release_reservation(mission.mission_id)
            self._audit("mission.rejected", mission.requested_by, {"mission_id": mission.mission_id, "code": error.code})
            raise

    def _dispatch(self, mission: Mission) -> dict[str, Any]:
        # 2. Safety first, and once. Everything downstream may assume it.
        if self.supervisor is not None:
            self.supervisor.permit_motion(requested_speed_mps=0.0, reservation_active=True)

        # 3. Only the leader dispatches.
        operation = self.lease.held() if self.lease is not None else None

        # 4. Selection across every registered vendor.
        address, considered = self.registry.select_vehicle(mission, minimum_battery=self.minimum_battery)
        if address is None:
            raise FaspError("resource.exhausted", "No eligible vehicle: " + "; ".join(f"{item['vehicle']}: {item['reason']}" for item in considered[:3]) or "no vehicles are registered.")
        fleet, vehicle_id = FleetRegistry.split(address)

        # 5. Ask the twin before asking the robot.
        preflight = self._preflight(mission, address, vehicle_id)
        if preflight is not None:
            self.missions.transition(mission.mission_id, {"ACCEPTED"}, "PREFLIGHT", preflight_json=preflight.to_dict())
            preflight.raise_if_infeasible()

        # 6. Reserve the predicted route before committing to it.
        reservation = self._reserve(mission, address, preflight)

        # 7. Fence check at the moment of effect, then dispatch.
        if self.lease is not None and operation is not None:
            self.lease.guard(operation)
        try:
            vendor = self.registry.dispatch(mission, address)
        except FaspError:
            self._release_reservation(mission.mission_id)
            raise

        self.missions.assign(mission.mission_id, address, fleet, operation.fence if operation else None, preflight.to_dict() if preflight else None)
        self._audit("mission.dispatched", mission.requested_by, {"mission_id": mission.mission_id, "vehicle": address, "fence": operation.fence if operation else None})
        return {
            "type": "mission.accepted",
            "duplicate": False,
            "mission_id": mission.mission_id,
            "state": MissionState.ASSIGNED.value,
            "vehicle": address,
            "vendor": vendor,
            "preflight": preflight.to_dict() if preflight else None,
            "reservation": reservation,
            "considered": considered,
        }

    def _preflight(self, mission: Mission, address: str, vehicle_id: str) -> PreflightResult | None:
        """Simulate, unless there is no site model or the twin is untrusted.

        A twin that has repeatedly diverged from this vehicle is *not* used
        to gate the mission: planning against a model known to be wrong is
        worse than not planning, because it is confidently wrong. The
        mission proceeds without twin evidence, and the fact is recorded.
        """
        if self.site is None:
            return None
        if self.twin is not None and not self.twin.trusted(vehicle_id):
            self._audit("mission.preflight_skipped", mission.requested_by, {"mission_id": mission.mission_id, "vehicle": address, "reason": "twin has diverged from this vehicle"})
            return None
        state = self.registry.vehicle_state(address)
        capabilities = self.registry.capabilities(address)
        return preflight_mission(
            mission,
            site=self.site,
            start_pose=state.pose or Pose(0.0, 0.0),
            vehicle_id=vehicle_id,
            battery_ratio=state.battery_ratio,
            capabilities=capabilities,
            reserve_battery=self.reserve_battery,
            occupied=self._existing_reservations(),
            now_ms=int(time.time() * 1000),
        )

    def _existing_reservations(self) -> list[dict[str, Any]]:
        if self.reservations is None:
            return []
        now_ms = int(time.time() * 1000)
        rows = self.db.read(
            "SELECT s.cell, s.start_ms, s.end_ms, r.owner FROM reservation_segments s JOIN reservations r ON r.reservation_id = s.reservation_id "
            "WHERE r.state = 'granted' AND r.lease_until_ms > ? LIMIT 4096",
            (now_ms,),
        )
        return [{"cell": row["cell"], "start_ms": int(row["start_ms"]), "end_ms": int(row["end_ms"]), "owner": row["owner"]} for row in rows]

    def _reserve(self, mission: Mission, address: str, preflight: PreflightResult | None) -> dict[str, Any] | None:
        """Reserve the predicted space-time route, if both are available.

        Predicted windows, not the whole route for the whole mission: a
        reservation that holds every cell from start to finish serialises
        the fleet down to one vehicle, which is the classic way a
        conservative traffic manager destroys throughput.
        """
        if self.reservations is None or preflight is None or not preflight.occupancy:
            return None
        segments = [{"cell": window["cell"], "start_ms": window["start_ms"], "end_ms": window["end_ms"]} for window in preflight.occupancy[:MAX_RESERVED_CELLS]]
        horizon = max(segment["end_ms"] for segment in segments) - int(time.time() * 1000)
        outcome = self.reservations.request(address, {"reservation_id": f"mission-{mission.mission_id}", "lease_ms": max(1_000, min(120_000, horizon + 2_000)), "segments": segments})
        if outcome.get("type") == "reservation.reject":
            raise FaspError("fleet.reservation_conflict", f"The predicted route conflicts with a granted reservation; retry after {outcome.get('retry_after_ms')}.")
        with self._lock:
            self._reserved[mission.mission_id] = address
        return outcome

    def _release_reservation(self, mission_id: str) -> None:
        if self.reservations is None:
            return
        with self._lock:
            owner = self._reserved.pop(mission_id, None)
        if owner is None:
            return
        try:
            self.reservations.release(owner, f"mission-{mission_id}")
        except FaspError:
            # Already released or expired. Releasing is idempotent by
            # intent; a failure here must not mask the outcome that
            # triggered it.
            return

    # -- lifecycle -----------------------------------------------------------
    def cancel(self, mission_id: str, requested_by: str) -> dict[str, Any]:
        record = self.missions.get(mission_id)
        if record is None:
            raise FaspError("schema.invalid", "Unknown mission_id.")
        if record["requested_by"] != requested_by:
            raise FaspError("auth.not_authorized", "Only the requesting peer may cancel this mission.")
        if record["state"] in {"COMPLETED", "FAILED", "CANCELLED", "REJECTED"}:
            return {"type": "mission.too_late", "mission_id": mission_id, "state": record["state"]}
        cancelled_at_vendor = False
        if record["fleet"]:
            try:
                cancelled_at_vendor = self.registry.cancel(record["fleet"], mission_id)
            except FaspError:
                cancelled_at_vendor = False
        self.missions.finish(mission_id, MissionState.CANCELLED.value, result={"cancelled_at_vendor": cancelled_at_vendor})
        self._release_reservation(mission_id)
        self._audit("mission.cancelled", requested_by, {"mission_id": mission_id, "at_vendor": cancelled_at_vendor})
        return {"type": "mission.cancelled", "mission_id": mission_id, "cancelled_at_vendor": cancelled_at_vendor}

    def status(self, mission_id: str) -> dict[str, Any]:
        record = self.missions.get(mission_id)
        if record is None:
            raise FaspError("schema.invalid", "Unknown mission_id.")
        return {"type": "mission.status", **self._render(record)}

    @staticmethod
    def _render(record: dict[str, Any] | None) -> dict[str, Any]:
        if record is None:
            return {"mission_id": None, "state": "REJECTED"}
        return {
            "mission_id": record["mission_id"],
            "state": record["state"],
            "vehicle": record["vehicle_id"],
            "preflight": record["preflight"],
            "result": record["result"],
            "error": record["error"],
            "updated_at": record["updated_at"],
        }

    # -- reconciliation --------------------------------------------------------
    def reconcile(self) -> dict[str, Any]:
        """Bring durable mission state back in line with the vendors'.

        Runs periodically (a `CyclicExecutor` is the natural driver) and is
        the reason a crash between "dispatched" and "recorded as dispatched"
        is recoverable rather than permanent: the vendor is the authority on
        what a vehicle is doing, and this is where that authority is read
        back.
        """
        summary = {"checked": 0, "updated": 0, "released": 0, "diverged": 0}
        for record in self.missions.active():
            summary["checked"] += 1
            fleet, mission_id = record["fleet"], record["mission_id"]
            if not fleet:
                continue
            try:
                state = self.registry.mission_state(fleet, mission_id)
            except FaspError:
                continue
            if state.terminal and self.missions.finish(mission_id, state.value, result={"reconciled": True, "at": stamp()}):
                summary["updated"] += 1
                self._release_reservation(mission_id)
                summary["released"] += 1
            elif state.value != record["state"]:
                self.missions.transition(mission_id, {record["state"]}, state.value)
                summary["updated"] += 1

        if self.twin is not None:
            for address, state in self.registry.list_vehicles():
                del address
                report = self.twin.observe(state)
                if report is not None and report.exceeded:
                    summary["diverged"] += 1
        return summary

    # -- safety ----------------------------------------------------------------
    def halt_all(self, reason: str, *, source: str = "coordinator", origin: str = "peer") -> dict[str, Any]:
        """Latch a supervisory halt and ask every vehicle to stop.

        Both, in that order, and neither depending on the other succeeding.
        The supervisor's latch is what stops *new* work regardless of what
        any vehicle does; the per-vehicle requests are best effort on top.
        And neither is an emergency stop: that remains the vehicles' own
        certified Layer 1 function, unreachable from here by design.
        """
        demand = self.supervisor.demand_halt(source, reason, origin=origin).to_dict() if self.supervisor is not None else None
        outcomes = self.registry.request_stop_all(reason)
        self._audit("fleet.halt_requested", source, {"reason": reason[:200], "vehicles": len(outcomes), "acknowledged": sum(1 for ok in outcomes.values() if ok)})
        return {
            "type": "fleet.halted",
            "reason": reason[:200],
            "supervisor_demand": demand,
            "vehicles": outcomes,
            "note": "This is a stop *request* at Layers 2-3. Each vehicle's certified protective stop is independent of it and cannot be cleared from here.",
        }

    def overview(self) -> dict[str, Any]:
        vehicles = [{"address": address, **state.to_dict()} for address, state in self.registry.list_vehicles()]
        return {
            "fleets": self.registry.describe(),
            "fleet_health": self.registry.health(),
            "vehicles": vehicles,
            "missions": self.missions.counts(),
            "safety": self.supervisor.status() if self.supervisor is not None else {"halt_requested": False, "note": "no safety supervisor configured"},
            "leadership": self.lease.observe() if self.lease is not None else {"holder": None, "note": "single-node deployment"},
            "twin": self.twin.summary() if self.twin is not None else {"samples": 0, "note": "no digital twin configured"},
        }

    # -- helpers ------------------------------------------------------------------
    def _audit(self, event: str, subject: str, detail: dict[str, Any]) -> None:
        if self.audit is None:
            return
        with self.db.write() as conn:
            self.audit.append(conn, event, subject, detail, stamp())

    def require_leadership(self) -> None:
        if self.lease is not None and not self.lease.is_leader:
            raise LeaseLost("This node is not the fleet coordinator; the standby does not dispatch.")
