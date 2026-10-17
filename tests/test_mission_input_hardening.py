"""Regression tests: malformed mission input is refused cleanly, never 500s.

A paired peer with `fleet.mission.v1` may send any JSON for a mission. Every
field the coordinator interprets must either be understood or produce a
`FaspError`/preflight refusal -- not a bare ValueError/TypeError from a
`dict(...)`/`float(...)` coercion, which used to escape `accept()` as a raw
500 and leave the mission row ACCEPTED (recorded, never dispatched, never
reconciled). A crashing vendor adapter follows the same rule: the mission
ends REJECTED with the reason attached.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import FaspHarness
from fasp_harness.edge.lease import LeaderLease
from fasp_harness.fleet.adapter import FleetRegistry
from fasp_harness.fleet.model import Mission, Pose
from fasp_harness.fleet.service import MissionService
from fasp_harness.fleet.simulated import SimulatedFleetManager
from fasp_harness.protocol.errors import FaspError
from fasp_harness.safety.drivers import SimulatedSafetyController
from fasp_harness.safety.interlock import SafetySupervisor
from fasp_harness.twin.kinematic import OccupancyGrid, SiteModel
from fasp_harness.twin.sync import TwinSync

NODES = {"start": Pose(0.0, 0.0), "dock-7": Pose(20.0, 0.0)}


class _CrashingFleet(SimulatedFleetManager):
    """A vendor adapter that starts raising after selection succeeded."""

    def dispatch(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        raise RuntimeError("vendor bus went away mid-dispatch")


class MissionInputHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)

        self.controller = SimulatedSafetyController()
        self.supervisor = SafetySupervisor(self.controller, stale_after_s=60.0)
        self.supervisor.poll()

        grid = OccupancyGrid(resolution_m=0.5)
        self.site = SiteModel(nodes=NODES, grid=grid)
        self.twin = TwinSync(position_tolerance_m=1.0)

        self.fleet = SimulatedFleetManager("acme", nodes=NODES)
        self.fleet.add_vehicle("AGV1", battery_ratio=0.95)
        self.registry = FleetRegistry()
        self.registry.register(self.fleet)

        self.coordinator = FaspHarness(root / "coordinator", "coordinator", "http://coordinator:8766", supervisor=self.supervisor)
        self.lease = LeaderLease(self.coordinator.db, node_id="node-a", ttl_s=60.0)
        self.lease.try_acquire()
        self.missions = self._service(self.registry)
        self.coordinator.missions = self.missions

        self.wms = FaspHarness(root / "wms", "wms", "http://wms:8766")
        hello = self.coordinator.hello(self.wms.id_card())
        self.coordinator.confirm_peer(self.wms.identity.system_id, hello["pair_code"], ["fleet.", "observe.", "safety."])

    def _service(self, registry: FleetRegistry) -> MissionService:
        return MissionService(
            self.coordinator.db,
            registry,
            audit=self.coordinator.audit,
            supervisor=self.supervisor,
            site=self.site,
            twin=self.twin,
            reservations=self.coordinator.reservations,
            lease=self.lease,
        )

    def tearDown(self) -> None:
        self.coordinator.close()
        self.wms.close()
        self.temp.cleanup()

    def dispatch(self, spec: dict[str, Any]) -> dict[str, Any]:
        return self.wms.make_envelope("mission.dispatch", self.coordinator.identity.system_id, spec)

    # -- malformed fields are refusals, not exceptions ----------------------

    def test_non_numeric_step_parameter_is_a_preflight_refusal(self) -> None:
        spec = {"mission_id": "bad-dwell", "steps": [{"kind": "wait", "parameters": {"duration_s": "banana"}}]}
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch(spec))
        self.assertEqual(raised.exception.code, "policy.preflight_failed")
        record = self.missions.missions.get("bad-dwell")
        self.assertEqual(record["state"], "REJECTED")
        self.assertIsNone(self.fleet.vehicle("AGV1").mission)

    def test_non_object_step_parameters_is_a_schema_refusal(self) -> None:
        spec = {"mission_id": "bad-params", "steps": [{"kind": "move", "node_id": "dock-7", "parameters": [1, 2]}]}
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch(spec))
        self.assertEqual(raised.exception.code, "schema.invalid")
        # Refused before durable admission: nothing to reconcile.
        self.assertIsNone(self.missions.missions.get("bad-params"))

    def test_non_object_mission_constraints_is_a_schema_refusal(self) -> None:
        spec = {"mission_id": "bad-constraints", "steps": [{"kind": "move", "node_id": "dock-7"}], "constraints": "fast"}
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch(spec))
        self.assertEqual(raised.exception.code, "schema.invalid")
        self.assertIsNone(self.missions.missions.get("bad-constraints"))

    def test_non_finite_pose_is_a_schema_refusal(self) -> None:
        spec = {"mission_id": "bad-pose", "steps": [{"kind": "move", "pose": {"x": "NaN", "y": 0.0}}]}
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch(spec))
        self.assertEqual(raised.exception.code, "schema.invalid")
        self.assertIsNone(self.missions.missions.get("bad-pose"))

    # -- a crashing vendor adapter still ends the mission --------------------

    def test_vendor_adapter_crash_is_a_clean_refusal(self) -> None:
        crashing = _CrashingFleet("acme", nodes=NODES)
        crashing.add_vehicle("AGV1", battery_ratio=0.95)
        registry = FleetRegistry()
        registry.register(crashing)
        service = self._service(registry)
        self.coordinator.missions = service

        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch({"mission_id": "vendor-crash", "steps": [{"kind": "move", "node_id": "dock-7"}]}))
        self.assertEqual(raised.exception.code, "transport.unreachable")
        record = service.missions.get("vendor-crash")
        self.assertEqual(record["state"], "REJECTED")
        # And the reservation taken for the doomed dispatch was released.
        self.assertEqual(service._reserved, {})

    def test_an_unexpected_pipeline_error_rejects_the_mission_and_500s_nothing(self) -> None:
        class _BrokenPreflight(MissionService):
            def _preflight(self, mission: Mission, address: str, vehicle_id: str) -> Any:
                raise RuntimeError("twin model exploded")

        service = _BrokenPreflight(
            self.coordinator.db,
            self.registry,
            audit=self.coordinator.audit,
            supervisor=self.supervisor,
            site=self.site,
            twin=self.twin,
            reservations=self.coordinator.reservations,
            lease=self.lease,
        )
        self.coordinator.missions = service

        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch({"mission_id": "pipeline-crash", "steps": [{"kind": "move", "node_id": "dock-7"}]}))
        self.assertEqual(raised.exception.code, "internal.adapter_error")
        record = service.missions.get("pipeline-crash")
        self.assertEqual(record["state"], "REJECTED")
        self.assertEqual(record["error"]["code"], "internal.adapter_error")
        self.assertIsNone(self.fleet.vehicle("AGV1").mission)


if __name__ == "__main__":
    unittest.main()
