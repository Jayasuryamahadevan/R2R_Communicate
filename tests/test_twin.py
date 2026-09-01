"""The digital twin: deterministic prediction, preflight, and divergence."""

from __future__ import annotations

import unittest

from fasp_harness.fleet.model import Mission, OperatingMode, Pose, StepKind, VehicleCapabilities, VehicleState
from fasp_harness.protocol.errors import FaspError
from fasp_harness.twin.kinematic import DifferentialDriveModel, OccupancyGrid, SiteModel, VehicleSim
from fasp_harness.twin.preflight import preflight_mission
from fasp_harness.twin.sync import TwinSync


def mission_to(*nodes: str, mission_id: str = "m1") -> Mission:
    return Mission.from_dict({"mission_id": mission_id, "steps": [{"kind": "move", "node_id": node} for node in nodes]}, requested_by="peer")


class KinematicTests(unittest.TestCase):
    def test_a_trapezoidal_profile_beats_a_constant_speed_estimate(self) -> None:
        """Accelerating and stopping at every waypoint is the dominant term
        a constant-speed estimate gets wrong on short hops."""
        model = DifferentialDriveModel(max_speed_mps=1.0, acceleration_mps2=0.5, deceleration_mps2=0.5)
        long_hop = model.segment_time_s(100.0)
        self.assertGreater(long_hop, 100.0 / 1.0, "A long hop must cost more than distance/speed.")
        short_hop = model.segment_time_s(0.5)
        self.assertGreater(short_hop, 0.5 / 1.0)
        self.assertEqual(model.segment_time_s(0.0), 0.0)

    def test_prediction_is_reproducible(self) -> None:
        def predict() -> dict:
            simulation = VehicleSim("v1", Pose(0.0, 0.0))
            outcome = simulation.travel_to(Pose(10.0, 5.0))
            return {"duration": outcome["duration_s"], "battery": simulation.battery_ratio, "elapsed": simulation.elapsed_s}

        self.assertEqual(predict(), predict())

    def test_travel_consumes_energy_and_waiting_consumes_less(self) -> None:
        moving = VehicleSim("v1", Pose(0.0, 0.0))
        moving.travel_to(Pose(50.0, 0.0))
        idle = VehicleSim("v2", Pose(0.0, 0.0))
        idle.wait(moving.elapsed_s)
        self.assertLess(moving.battery_ratio, idle.battery_ratio)

    def test_the_grid_reports_the_cells_a_route_actually_crosses(self) -> None:
        grid = OccupancyGrid(resolution_m=1.0)
        grid.block_rectangle(5.0, -1.0, 6.0, 1.0)
        self.assertTrue(grid.blocked_on(Pose(0.0, 0.0), Pose(10.0, 0.0)))
        self.assertFalse(grid.blocked_on(Pose(0.0, 10.0), Pose(10.0, 10.0)))

    def test_an_unknown_node_is_a_clean_error(self) -> None:
        with self.assertRaises(FaspError):
            SiteModel().pose_of("nowhere")


class PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        grid = OccupancyGrid(resolution_m=0.5)
        grid.block_rectangle(20.0, -3.0, 22.0, 3.0)
        self.site = SiteModel(nodes={"start": Pose(0.0, 0.0), "near": Pose(5.0, 0.0), "far": Pose(60.0, 0.0), "side": Pose(0.0, 40.0)}, grid=grid)

    def test_a_feasible_mission_is_accepted_with_an_estimate(self) -> None:
        result = preflight_mission(mission_to("near"), site=self.site, start_pose=Pose(0.0, 0.0))
        self.assertTrue(result.feasible, result.reasons)
        self.assertGreater(result.estimated_duration_s, 0.0)
        self.assertAlmostEqual(result.distance_m, 5.0, places=3)
        self.assertTrue(result.occupancy)

    def test_a_route_through_a_known_obstacle_is_refused(self) -> None:
        result = preflight_mission(mission_to("far"), site=self.site, start_pose=Pose(0.0, 0.0))
        self.assertFalse(result.feasible)
        self.assertIn("blocked", result.reasons[0])

    def test_a_mission_that_would_flatten_the_battery_is_refused(self) -> None:
        """Modelled per vehicle: a tugger with a small pack and a hungry
        drive cannot do a trip an AMR with a big pack can."""
        site = SiteModel(nodes=self.site.nodes, vehicles={"hungry": DifferentialDriveModel(battery_wh=2.0, moving_power_w=180.0)})
        refused = preflight_mission(mission_to("side"), site=site, start_pose=Pose(0.0, 0.0), vehicle_id="hungry", battery_ratio=0.5, reserve_battery=0.10)
        self.assertFalse(refused.feasible)
        self.assertTrue(any("reserve" in reason for reason in refused.reasons), refused.reasons)

        allowed = preflight_mission(mission_to("side"), site=SiteModel(nodes=self.site.nodes), start_pose=Pose(0.0, 0.0), battery_ratio=0.5, reserve_battery=0.10)
        self.assertTrue(allowed.feasible, allowed.reasons)

    def test_a_mission_that_cannot_meet_its_deadline_is_refused(self) -> None:
        result = preflight_mission(mission_to("side"), site=self.site, start_pose=Pose(0.0, 0.0), deadline_s=1.0)
        self.assertFalse(result.feasible)
        self.assertTrue(any("deadline" in reason for reason in result.reasons))

    def test_a_vehicle_that_cannot_do_a_step_is_refused(self) -> None:
        mission = Mission.from_dict({"steps": [{"kind": "move", "node_id": "near"}, {"kind": "pick", "node_id": "near"}]}, requested_by="peer")
        result = preflight_mission(mission, site=self.site, start_pose=Pose(0.0, 0.0), capabilities=VehicleCapabilities(supported_steps=(StepKind.MOVE,)))
        self.assertFalse(result.feasible)

    def test_a_space_time_conflict_is_found_before_dispatch(self) -> None:
        """Same cell at a different time is fine -- that is the entire point
        of reserving space-time rather than space."""
        clear = preflight_mission(mission_to("near"), site=self.site, start_pose=Pose(0.0, 0.0))
        cell = clear.occupancy[1]["cell"]

        conflicting = preflight_mission(
            mission_to("near"),
            site=self.site,
            start_pose=Pose(0.0, 0.0),
            occupied=[{"cell": cell, "start_ms": 0, "end_ms": 60_000, "owner": "sim:AGV9"}],
        )
        self.assertFalse(conflicting.feasible)
        self.assertIn("AGV9", conflicting.reasons[0])

        later = preflight_mission(
            mission_to("near"),
            site=self.site,
            start_pose=Pose(0.0, 0.0),
            occupied=[{"cell": cell, "start_ms": 3_600_000, "end_ms": 3_660_000, "owner": "sim:AGV9"}],
        )
        self.assertTrue(later.feasible, later.reasons)

    def test_an_unknown_node_fails_preflight_rather_than_dispatch(self) -> None:
        result = preflight_mission(mission_to("nowhere"), site=self.site, start_pose=Pose(0.0, 0.0))
        self.assertFalse(result.feasible)
        self.assertIn("Unknown map node", result.reasons[0])

    def test_a_cross_map_mission_is_refused(self) -> None:
        site = SiteModel(nodes={"other": Pose(1.0, 1.0, map_id="floor2")})
        result = preflight_mission(mission_to("other"), site=site, start_pose=Pose(0.0, 0.0, map_id="floor1"))
        self.assertFalse(result.feasible)
        self.assertIn("between maps", result.reasons[0])

    def test_the_occupancy_evidence_is_bounded(self) -> None:
        result = preflight_mission(mission_to("side"), site=self.site, start_pose=Pose(0.0, 0.0))
        self.assertLessEqual(len(result.occupancy), 64)

    def test_raise_if_infeasible_carries_the_reason(self) -> None:
        result = preflight_mission(mission_to("far"), site=self.site, start_pose=Pose(0.0, 0.0))
        with self.assertRaises(FaspError) as raised:
            result.raise_if_infeasible()
        self.assertEqual(raised.exception.code, "policy.preflight_failed")


def a_state(x: float, y: float, vehicle_id: str = "v1") -> VehicleState:
    return VehicleState(
        vehicle_id=vehicle_id,
        fleet="sim",
        online=True,
        operating_mode=OperatingMode.AUTOMATIC,
        pose=Pose(x, y),
        battery_ratio=0.9,
        charging=False,
        driving=True,
        paused=False,
    )


class TwinSyncTests(unittest.TestCase):
    def test_a_single_spike_does_not_escalate(self) -> None:
        """Localisation jitter, a late frame, and a pause for a pedestrian
        all produce one-off spikes. Requiring N in a row is what makes the
        signal actionable."""
        escalations: list = []
        sync = TwinSync(position_tolerance_m=1.0, consecutive_threshold=3, on_divergence=escalations.append)
        sync.predict("v1", Pose(0.0, 0.0))
        report = sync.observe(a_state(5.0, 0.0))
        self.assertTrue(report.exceeded)
        self.assertEqual(escalations, [])
        self.assertTrue(sync.trusted("v1"))

    def test_sustained_divergence_escalates_and_withdraws_trust(self) -> None:
        escalations: list = []
        sync = TwinSync(position_tolerance_m=1.0, consecutive_threshold=3, on_divergence=escalations.append)
        for step in range(4):
            sync.predict("v1", Pose(0.0, 0.0))
            sync.observe(a_state(5.0 + step, 0.0))
        self.assertTrue(escalations)
        self.assertFalse(sync.trusted("v1"))

    def test_a_very_large_divergence_can_request_a_halt(self) -> None:
        halts: list = []
        sync = TwinSync(position_tolerance_m=1.0, halt_tolerance_m=5.0, consecutive_threshold=2, on_halt_required=halts.append)
        for _ in range(3):
            sync.predict("v1", Pose(0.0, 0.0))
            sync.observe(a_state(50.0, 0.0))
        self.assertTrue(halts)

    def test_a_recovered_vehicle_regains_trust(self) -> None:
        """Divergence is measured against a *fresh* prediction each cycle, so
        a vehicle that starts matching its prediction again is believed
        again -- without which one bad minute would blind the twin forever."""
        sync = TwinSync(position_tolerance_m=1.0, consecutive_threshold=2)
        for step in range(3):
            sync.predict("v1", Pose(0.0, 0.0))
            sync.observe(a_state(5.0 + step, 0.0))
        self.assertFalse(sync.trusted("v1"))

        sync.predict("v1", Pose(7.0, 0.0))
        report = sync.observe(a_state(7.0, 0.0))
        self.assertFalse(report.exceeded)
        self.assertTrue(sync.trusted("v1"))

    def test_a_stationary_discrepancy_registers_once_because_the_twin_re_anchors(self) -> None:
        """A twin that kept predicting from a stale pose would report the
        same divergence forever and never notice the vehicle recovering."""
        sync = TwinSync(position_tolerance_m=1.0, consecutive_threshold=2)
        sync.predict("v1", Pose(0.0, 0.0))
        self.assertTrue(sync.observe(a_state(5.0, 0.0)).exceeded)
        self.assertFalse(sync.observe(a_state(5.0, 0.0)).exceeded)

    def test_the_first_observation_only_seeds_the_prediction(self) -> None:
        sync = TwinSync()
        self.assertIsNone(sync.observe(a_state(9.0, 9.0)))

    def test_a_vehicle_without_a_pose_is_skipped(self) -> None:
        sync = TwinSync()
        state = VehicleState(vehicle_id="v1", fleet="sim", online=True, operating_mode=OperatingMode.AUTOMATIC, pose=None, battery_ratio=1.0, charging=False, driving=False, paused=False)
        self.assertIsNone(sync.observe(state))

    def test_history_is_bounded_and_summarised(self) -> None:
        sync = TwinSync(position_tolerance_m=0.5)
        sync.predict("v1", Pose(0.0, 0.0))
        for index in range(600):
            sync.observe(a_state(float(index), 0.0))
        summary = sync.summary()
        self.assertEqual(summary["samples"], 512)
        self.assertGreater(summary["worst_error_m"], 0.0)
        self.assertLessEqual(len(sync.history(limit=10)), 10)


if __name__ == "__main__":
    unittest.main()
