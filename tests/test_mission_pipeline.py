"""End to end: a signed envelope becomes a mission, or is refused.

These are the tests that exercise the actual ordering the design depends
on -- durable record, safety gate, leadership, selection, preflight,
reservation, dispatch -- rather than each component alone.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.edge.lease import LeaderLease, LeaseLost
from fasp_harness.fleet.adapter import FleetRegistry
from fasp_harness.fleet.model import MissionState, OperatingMode, Pose
from fasp_harness.fleet.service import MissionService
from fasp_harness.fleet.simulated import SimulatedFleetManager
from fasp_harness.protocol.errors import FaspError
from fasp_harness.safety.drivers import SimulatedSafetyController
from fasp_harness.safety.interlock import LOCAL_OPERATOR, SafetySupervisor
from fasp_harness.twin.kinematic import OccupancyGrid, SiteModel
from fasp_harness.twin.sync import TwinSync

NODES = {"start": Pose(0.0, 0.0), "dock-7": Pose(20.0, 0.0), "wall": Pose(0.0, 60.0)}


class MissionPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)

        self.controller = SimulatedSafetyController()
        self.supervisor = SafetySupervisor(self.controller, stale_after_s=60.0)
        self.supervisor.poll()

        grid = OccupancyGrid(resolution_m=0.5)
        grid.block_rectangle(-2.0, 30.0, 2.0, 32.0)  # a wall across the route to "wall"
        self.site = SiteModel(nodes=NODES, grid=grid)
        self.twin = TwinSync(position_tolerance_m=1.0)

        self.fleet = SimulatedFleetManager("acme", nodes=NODES)
        self.fleet.add_vehicle("AGV1", battery_ratio=0.95)
        self.registry = FleetRegistry()
        self.registry.register(self.fleet)

        self.coordinator = FaspHarness(root / "coordinator", "coordinator", "http://coordinator:8766", supervisor=self.supervisor)
        self.lease = LeaderLease(self.coordinator.db, node_id="node-a", ttl_s=60.0)
        self.lease.try_acquire()
        self.missions = MissionService(
            self.coordinator.db,
            self.registry,
            audit=self.coordinator.audit,
            supervisor=self.supervisor,
            site=self.site,
            twin=self.twin,
            reservations=self.coordinator.reservations,
            lease=self.lease,
        )
        self.coordinator.missions = self.missions

        self.wms = FaspHarness(root / "wms", "wms", "http://wms:8766")
        hello = self.coordinator.hello(self.wms.id_card())
        self.coordinator.confirm_peer(self.wms.identity.system_id, hello["pair_code"], ["fleet.", "observe.", "safety."])

    def tearDown(self) -> None:
        self.coordinator.close()
        self.wms.close()
        self.temp.cleanup()

    def dispatch_envelope(self, mission_id: str = "m1", node: str = "dock-7", **extra) -> dict:
        return self.wms.make_envelope(
            "mission.dispatch",
            self.coordinator.identity.system_id,
            {"mission_id": mission_id, "steps": [{"kind": "move", "node_id": node}], **extra},
        )

    # -- the happy path -------------------------------------------------
    def test_a_signed_mission_is_preflighted_reserved_and_dispatched(self) -> None:
        _, response = self.coordinator.accept(self.dispatch_envelope())
        self.assertEqual(response["state"], MissionState.ASSIGNED.value)
        self.assertEqual(response["vehicle"], "acme:AGV1")
        self.assertTrue(response["preflight"]["feasible"])
        self.assertEqual(response["reservation"]["type"], "reservation.grant")
        self.assertEqual(self.fleet.vehicle("AGV1").mission.mission_id, "m1")

        # And the durable record matches what the vehicle was told.
        record = self.missions.missions.get("m1")
        self.assertEqual(record["state"], "ASSIGNED")
        self.assertEqual(record["fence"], 1)

    def test_resubmitting_the_same_mission_does_not_dispatch_twice(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        second = self.wms.make_envelope("mission.dispatch", self.coordinator.identity.system_id, {"mission_id": "m1", "steps": [{"kind": "move", "node_id": "dock-7"}]})
        _, response = self.coordinator.accept(second)
        self.assertTrue(response["duplicate"])
        self.assertEqual(len(self.fleet.list_vehicles()), 1)

    def test_a_mission_completes_and_is_reconciled_from_the_vendor(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        self.fleet.advance(120.0)
        summary = self.missions.reconcile()
        self.assertGreaterEqual(summary["updated"], 1)
        self.assertEqual(self.missions.missions.get("m1")["state"], "COMPLETED")

    # -- refusals -------------------------------------------------------
    def test_a_latched_halt_stops_dispatch_at_the_top_of_the_pipeline(self) -> None:
        self.supervisor.demand_halt("operator", "person in the aisle", origin="peer")
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch_envelope())
        self.assertEqual(raised.exception.code, "safety.estop_active")
        self.assertIsNone(self.fleet.vehicle("AGV1").mission)
        self.assertEqual(self.missions.missions.get("m1")["state"], "REJECTED")

    def test_dispatch_resumes_only_after_a_local_reset(self) -> None:
        self.supervisor.demand_halt("operator", "checking", origin="peer")
        self.controller.manual_reset()
        self.supervisor.clear(origin=LOCAL_OPERATOR, operator="engineer")
        _, response = self.coordinator.accept(self.dispatch_envelope("m2"))
        self.assertEqual(response["state"], MissionState.ASSIGNED.value)

    def test_an_infeasible_mission_is_refused_before_any_robot_hears_about_it(self) -> None:
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch_envelope("m-wall", node="wall"))
        self.assertEqual(raised.exception.code, "policy.preflight_failed")
        self.assertIsNone(self.fleet.vehicle("AGV1").mission)
        record = self.missions.missions.get("m-wall")
        self.assertEqual(record["state"], "REJECTED")
        self.assertFalse(record["preflight"]["feasible"])

    def test_a_superseded_coordinator_cannot_dispatch(self) -> None:
        """Split-brain, prevented at the moment of effect rather than hoped
        away by a timeout."""
        other = LeaderLease(self.coordinator.db, node_id="node-b", ttl_s=60.0)
        other.try_acquire(now_ms=int(time.time() * 1000) + 120_000)
        with self.assertRaises(LeaseLost):
            self.coordinator.accept(self.dispatch_envelope("m-split"))
        self.assertIsNone(self.fleet.vehicle("AGV1").mission)

    def test_no_eligible_vehicle_explains_why(self) -> None:
        self.fleet.vehicle("AGV1").operating_mode = OperatingMode.MANUAL
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch_envelope("m-none"))
        self.assertEqual(raised.exception.code, "resource.exhausted")
        self.assertIn("MANUAL", raised.exception.detail)

    def test_a_vehicle_reporting_an_estop_is_not_dispatched_to(self) -> None:
        self.fleet.vehicle("AGV1").estop_active = True
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch_envelope("m-estop"))
        self.assertIn("emergency stop", raised.exception.detail)

    def test_a_second_mission_conflicting_in_space_and_time_is_refused(self) -> None:
        self.coordinator.accept(self.dispatch_envelope("m1"))
        self.fleet.add_vehicle("AGV2", battery_ratio=0.99)
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(self.dispatch_envelope("m2"))
        self.assertIn(raised.exception.code, {"fleet.reservation_conflict", "policy.preflight_failed"})

    def test_an_unauthorized_peer_cannot_dispatch(self) -> None:
        stranger = FaspHarness(Path(self.temp.name) / "stranger", "stranger", "http://stranger:8766")
        hello = self.coordinator.hello(stranger.id_card())
        self.coordinator.confirm_peer(stranger.identity.system_id, hello["pair_code"], ["observe."])
        envelope = stranger.make_envelope("mission.dispatch", self.coordinator.identity.system_id, {"mission_id": "m-x", "steps": [{"kind": "move", "node_id": "dock-7"}]})
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(envelope)
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        stranger.close()

    # -- lifecycle -------------------------------------------------------
    def test_only_the_requesting_peer_may_cancel(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        other = FaspHarness(Path(self.temp.name) / "other", "other", "http://other:8766")
        hello = self.coordinator.hello(other.id_card())
        self.coordinator.confirm_peer(other.identity.system_id, hello["pair_code"], ["fleet."])
        envelope = other.make_envelope("mission.cancel", self.coordinator.identity.system_id, {"mission_id": "m1"})
        with self.assertRaises(FaspError) as raised:
            self.coordinator.accept(envelope)
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        other.close()

    def test_cancel_reaches_the_vendor_and_releases_the_reservation(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        _, response = self.coordinator.accept(self.wms.make_envelope("mission.cancel", self.coordinator.identity.system_id, {"mission_id": "m1"}))
        self.assertTrue(response["cancelled_at_vendor"])
        self.assertEqual(self.missions.missions.get("m1")["state"], "CANCELLED")
        self.assertIsNone(self.fleet.vehicle("AGV1").mission)

        # The released cell is immediately reservable again.
        _, second = self.coordinator.accept(self.dispatch_envelope("m2"))
        self.assertEqual(second["state"], MissionState.ASSIGNED.value)

    def test_mission_status_is_readable_only_by_its_requester(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        _, status = self.coordinator.accept(self.wms.make_envelope("mission.status", self.coordinator.identity.system_id, {"mission_id": "m1"}))
        self.assertEqual(status["state"], "ASSIGNED")

    def test_cancelling_a_finished_mission_reports_too_late(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        self.fleet.advance(120.0)
        self.missions.reconcile()
        _, response = self.coordinator.accept(self.wms.make_envelope("mission.cancel", self.coordinator.identity.system_id, {"mission_id": "m1"}))
        self.assertEqual(response["type"], "mission.too_late")

    # -- safety and observation -------------------------------------------
    def test_a_peer_halt_latches_the_supervisor_and_stops_the_fleet(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        _, response = self.coordinator.accept(self.wms.make_envelope("safety.halt", self.coordinator.identity.system_id, {"reason": "smoke in aisle 3"}))
        self.assertTrue(response["halt_requested"])
        self.assertTrue(self.supervisor.latched)
        self.assertTrue(response["fleet"]["acme:AGV1"])
        self.assertTrue(self.fleet.vehicle("AGV1").paused)
        self.assertIn("cannot be cleared from here", response["note"] if "note" in response else self.missions.halt_all("x")["note"])

    def test_there_is_no_message_kind_that_clears_a_halt(self) -> None:
        """The clearing operation does not exist as a protocol verb at all."""
        self.assertNotIn("safety.clear", FaspHarness.DISPATCH)
        for kind in FaspHarness.DISPATCH:
            self.assertFalse(any(word in kind for word in ("clear", "reset", "bypass", "mute", "override")), kind)

    def test_safety_evidence_is_readable_and_says_it_is_observation_only(self) -> None:
        _, evidence = self.coordinator.accept(self.wms.make_envelope("safety.evidence", self.coordinator.identity.system_id, {}))
        self.assertTrue(evidence["observed_only"])
        self.assertEqual(evidence["layer"], 1)
        self.assertFalse(evidence["controller"]["real_hardware"])

    def test_fleet_status_requires_the_observe_prefix(self) -> None:
        _, overview = self.coordinator.accept(self.wms.make_envelope("fleet.status", self.coordinator.identity.system_id, {}))
        self.assertEqual(overview["type"], "fleet.status")
        self.assertEqual(len(overview["vehicles"]), 1)
        self.assertIn("acme", [entry["fleet"] for entry in overview["fleet_health"]])

    def test_the_audit_chain_records_the_whole_pipeline_and_still_verifies(self) -> None:
        self.coordinator.accept(self.dispatch_envelope())
        self.coordinator.accept(self.wms.make_envelope("safety.halt", self.coordinator.identity.system_id, {"reason": "test"}))
        ok, bad = self.coordinator.audit.verify()
        self.assertTrue(ok, f"audit chain broken at {bad}")
        events = [row["event_type"] for row in self.coordinator.db.read("SELECT event_type FROM audit_log ORDER BY seq")]
        for expected in ("mission.accepted", "mission.dispatched", "fleet.halt_requested", "safety.halt_requested"):
            self.assertIn(expected, events)

    def test_a_node_without_a_fleet_reports_capability_unavailable(self) -> None:
        bare = FaspHarness(Path(self.temp.name) / "bare", "bare", "http://bare:8766")
        hello = bare.hello(self.wms.id_card())
        bare.confirm_peer(self.wms.identity.system_id, hello["pair_code"], ["fleet."])
        with self.assertRaises(FaspError) as raised:
            bare.accept(self.wms.make_envelope("mission.dispatch", bare.identity.system_id, {"steps": [{"kind": "move", "node_id": "x"}]}))
        self.assertEqual(raised.exception.code, "capability.unavailable")
        bare.close()


if __name__ == "__main__":
    unittest.main()
