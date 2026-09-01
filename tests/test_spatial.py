"""End to end: a drone and a ground robot meeting in one shared space.

The unit tests check each piece. This one checks that they compose, which
is the part that actually decides whether the design works -- a clock
bound that never reaches a guard band, or a frame error that never reaches
a separation verdict, would pass every test in every other file and be
useless in a warehouse.

The scenario is the one the design was written for: two machines with no
shared clock, no shared frame, and a radio between them, deciding whether
they may proceed and who may tell whom to move.
"""

from __future__ import annotations

import io
import json
import random
import unittest
from contextlib import redirect_stdout

from fasp_harness.spatial import (
    Aerial,
    ClockTracker,
    Exchange,
    GroundVehicle,
    GuardPolicy,
    Morphology,
    SpatialDelegation,
    StateReport,
    TimeInterval,
    Volume,
    align_frames,
    check_separation,
    envelope_for,
)
from fasp_harness.spatial.frames import FrameGraph, Rigid3
from fasp_harness.spatial.linalg import identity, mat_scale

# Five markers the two robots can both range to, spread in all three axes
# so the alignment is well conditioned.
SHARED_MARKERS = [[0.0, 0.0, 0.0], [6.0, 0.0, 0.0], [0.0, 8.0, 0.0], [2.0, 2.0, 3.0], [5.0, 6.0, 1.0]]

# The drone's ENU frame is rotated 30 degrees and offset from the ground
# robot's map frame. Neither knows this; it is what gets estimated.
TRUE_ALIGNMENT = Rigid3(
    [[0.8660254037844387, -0.5, 0.0], [0.5, 0.8660254037844387, 0.0], [0.0, 0.0, 1.0]],
    [12.0, -4.0, 0.0],
)

ONBOARD = mat_scale(identity(6), 0.01)


def _sync_clocks(*, samples: int = 30, floor_ms: float = 20.0, seed: int = 11) -> tuple[ClockTracker, float]:
    """Run a realistic exchange over a queueing link. Returns the tracker
    and the true offset at the reference instant."""
    tracker = ClockTracker()
    generator = random.Random(seed)
    true_offset_ms, drift_ppm = 850.0, 35.0
    for index in range(samples):
        local_send = index * 1_500.0
        offset = true_offset_ms + drift_ppm * 1e-6 * local_send
        round_trip = floor_ms + (180.0 if index % 4 == 0 else generator.random() * 6.0)
        forward = round_trip / 2.0
        remote_receive = local_send + forward + offset
        tracker.observe(Exchange(local_send, remote_receive, remote_receive + 1.0, local_send + round_trip + 1.0))
    reference = (samples - 1) * 1_500.0
    return tracker, true_offset_ms + drift_ppm * 1e-6 * reference


class AirGroundScenario(unittest.TestCase):
    def setUp(self) -> None:
        self.tracker, self.true_offset_ms = _sync_clocks()
        self.estimate = self.tracker.estimate()
        self.stamp_half_width_ms = self.estimate.uncertainty_at(self.estimate.reference_local_ms)

        self.graph = FrameGraph()
        self.graph.add(
            align_frames(
                SHARED_MARKERS,
                [TRUE_ALIGNMENT.apply(point) for point in SHARED_MARKERS],
                source_frame="uav-1/enu",
                target_frame="ugv-1/map",
                observed_at=TimeInterval(0.0, self.stamp_half_width_ms),
                method="uwb",
                measurement_sigma_m=0.05,
            )
        )
        self.policy = GuardPolicy(risk_alpha=1e-6, dimensions=3, latency_margin_s=0.2, control_period_s=0.1)

    def _drone(self, position: list[float], velocity: list[float] | None = None) -> StateReport:
        return StateReport(
            "uav-1",
            "uav-1/enu",
            position,
            velocity or [1.0, 0.0, 0.0],
            ONBOARD,
            TimeInterval(0.0, self.stamp_half_width_ms),
            Aerial(),
            12.0,
        )

    def _ground(self, position: list[float]) -> StateReport:
        return StateReport(
            "ugv-1",
            "ugv-1/map",
            position,
            [1.2, 0.0, 0.0],
            ONBOARD,
            TimeInterval(0.0, self.stamp_half_width_ms),
            GroundVehicle(),
            1.8,
        )

    # -- the chain, one link at a time ---------------------------------

    def test_the_clocks_agree_to_within_the_bound_they_claim(self) -> None:
        """Step one. Everything downstream is a lie if this is."""
        interval = self.estimate.to_remote(self.estimate.reference_local_ms)
        self.assertTrue(interval.contains(self.estimate.reference_local_ms + self.true_offset_ms))
        self.assertTrue(self.estimate.skew_measured)
        self.assertLess(self.stamp_half_width_ms, 20.0)

    def test_the_frames_are_recovered_without_either_robot_knowing_the_answer(self) -> None:
        """Step two. Neither platform was told the 30 degree rotation."""
        link = self.graph.lookup("uav-1/enu", "ugv-1/map")
        self.assertLess(max(abs(a - b) for a, b in zip(link.transform.translation, TRUE_ALIGNMENT.translation, strict=True)), 0.05)
        self.assertGreater(link.position_sigma_m(), 0.0)

    def test_a_drone_position_becomes_meaningful_in_the_ground_robots_frame(self) -> None:
        """Step three. The two claims become commensurable, and the price
        of making them so is visible in the covariance."""
        link = self.graph.lookup("uav-1/enu", "ugv-1/map")
        report = self._drone([2.0, 2.0, 6.0])
        crossed = report.in_frame(link)

        self.assertEqual(crossed.frame_id, "ugv-1/map")
        expected = TRUE_ALIGNMENT.apply([2.0, 2.0, 6.0])
        self.assertLess(max(abs(a - b) for a, b in zip(crossed.position_m, expected, strict=True)), 0.2)
        # Crossing a frame boundary costs certainty, and that cost is real.
        self.assertGreater(crossed.position_sigma_m(), report.position_sigma_m())

    def test_the_drone_clears_the_ground_robot_at_altitude_and_conflicts_on_descent(self) -> None:
        """Step four. The decision, and the one that made this design
        cross-domain: no altitude special-casing appears anywhere."""
        link = self.graph.lookup("uav-1/enu", "ugv-1/map")
        ground = envelope_for(self._ground([12.0, -4.0, 0.0]), self.policy, 0.0, morphology=Morphology.GROUND, body_radius_m=0.45)

        high = envelope_for(self._drone([0.0, 0.0, 25.0]).in_frame(link), self.policy, 0.0, morphology=Morphology.AIR, body_radius_m=0.35)
        self.assertTrue(check_separation(ground, high).clear)

        landing = envelope_for(
            self._drone([0.0, 0.0, 0.4], velocity=[0.0, 0.0, -0.3]).in_frame(link),
            self.policy,
            0.0,
            morphology=Morphology.AIR,
            body_radius_m=0.35,
        )
        self.assertFalse(check_separation(ground, landing).clear)

    def test_authority_is_delegated_bounded_and_then_expires(self) -> None:
        """Step five. The drone may append a waypoint to the ground
        robot's queue -- inside one volume, under one speed cap, for
        thirty seconds."""
        delegation = SpatialDelegation(
            holder="uav-1",
            subject="ugv-1",
            capability="fleet.waypoint.append",
            volume=Volume("ugv-1/map", [-30.0, -30.0, -6.0], [30.0, 30.0, 20.0]),
            not_before_ms=0.0,
            not_after_ms=30_000.0,
            max_speed_mps=1.5,
            morphologies=frozenset({Morphology.GROUND}),
        )
        envelope = envelope_for(self._ground([0.0, 0.0, 0.0]), self.policy, 0.0, morphology=Morphology.GROUND, body_radius_m=0.45)

        self.assertTrue(delegation.authorise(envelope, 5_000.0, requested_speed_mps=1.2).permitted)
        self.assertFalse(delegation.authorise(envelope, 5_000.0, requested_speed_mps=1.8).permitted)
        self.assertFalse(delegation.authorise(envelope, 31_000.0).permitted)

    # -- what happens when the link degrades ---------------------------

    def test_a_degrading_link_widens_every_downstream_bound_in_order(self) -> None:
        """The property the whole package exists to provide.

        A worse radio does not produce a worse answer -- it produces a
        wider, still-correct one, and every stage passes the widening on
        rather than absorbing it.
        """
        good, _ = _sync_clocks(floor_ms=8.0)
        bad, _ = _sync_clocks(floor_ms=400.0)
        good_slop = good.estimate().uncertainty_at(good.estimate().reference_local_ms)
        bad_slop = bad.estimate().uncertainty_at(bad.estimate().reference_local_ms)
        self.assertGreater(bad_slop, good_slop)

        def band(half_width_ms: float) -> float:
            report = StateReport(
                "ugv-1",
                "ugv-1/map",
                [0.0, 0.0, 0.0],
                [1.2, 0.0, 0.0],
                ONBOARD,
                TimeInterval(0.0, half_width_ms),
                GroundVehicle(),
                1.8,
            )
            return envelope_for(report, self.policy, 0.0, morphology=Morphology.GROUND, body_radius_m=0.45).radius_m

        self.assertGreater(band(bad_slop), band(good_slop))

    def test_silence_closes_the_gap_between_two_robots_that_never_moved(self) -> None:
        """Nothing moved. The system merely lost the ability to prove that
        nothing moved, and a coordination refusal is the correct response
        to losing evidence."""
        first = self._ground([0.0, 0.0, 0.0])
        second = StateReport("ugv-2", "ugv-1/map", [7.0, 0.0, 0.0], [1.2, 0.0, 0.0], ONBOARD, TimeInterval(0.0, self.stamp_half_width_ms), GroundVehicle(), 1.8)

        def verdict(now_ms: float) -> bool:
            return check_separation(
                envelope_for(first, self.policy, now_ms, morphology=Morphology.GROUND, body_radius_m=0.45),
                envelope_for(second, self.policy, now_ms, morphology=Morphology.GROUND, body_radius_m=0.45),
            ).clear

        self.assertTrue(verdict(0.0))
        self.assertFalse(verdict(4_000.0))

    def test_a_stale_frame_link_is_what_actually_breaks_first(self) -> None:
        """The result that argues for re-ranging rather than re-reporting.

        Both robots keep reporting perfectly. The alignment between them
        goes unmeasured for two minutes, and that alone is enough to make
        the pair uncoordinatable -- the frame link, not the state reports,
        is the term that dominates.
        """
        drifting = align_frames(
            SHARED_MARKERS,
            [TRUE_ALIGNMENT.apply(point) for point in SHARED_MARKERS],
            source_frame="uav-1/enu",
            target_frame="ugv-1/map",
            observed_at=TimeInterval(0.0, self.stamp_half_width_ms),
            method="visual",
            measurement_sigma_m=0.05,
        )
        fresh = self._drone([2.0, 2.0, 6.0]).in_frame(drifting, now_ms=0.0)
        stale = self._drone([2.0, 2.0, 6.0]).in_frame(drifting, now_ms=120_000.0)
        self.assertLess(fresh.position_sigma_m(), 0.5)
        self.assertGreater(stale.position_sigma_m(), 5.0)

    def test_the_whole_chain_produces_an_explainable_verdict(self) -> None:
        """A separation decision nobody can reconstruct afterwards is not
        evidence, whatever it says. Every number that produced the answer
        survives into the record."""
        link = self.graph.lookup("uav-1/enu", "ugv-1/map")
        verdict = check_separation(
            envelope_for(self._ground([12.0, -4.0, 0.0]), self.policy, 0.0, morphology=Morphology.GROUND, body_radius_m=0.45),
            envelope_for(self._drone([0.0, 0.0, 1.0]).in_frame(link), self.policy, 0.0, morphology=Morphology.AIR, body_radius_m=0.35),
        )
        payload = verdict.to_dict()
        self.assertAlmostEqual(payload["margin_m"], payload["distance_m"] - payload["required_m"], places=9)
        self.assertEqual(payload["first"]["risk_alpha"], 1e-6)
        self.assertIn(payload["first"]["basis"], {"statistical", "reachable"})
        self.assertEqual(payload["second"]["morphology"], "air")


class GuardBudgetCommandTests(unittest.TestCase):
    """`python -m fasp_harness guard-budget` -- the integrator's question.

    The exit code is a pipeline contract, so it is asserted rather than
    assumed: a band that outgrows the available clearance must fail the
    command, not merely mention it in prose nobody greps.
    """

    def _run(self, *argv: str) -> tuple[int, str]:
        from fasp_harness import cli

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["guard-budget", *argv])
        return code, buffer.getvalue()

    def test_a_generous_clearance_passes(self) -> None:
        code, output = self._run("--round-trip-ms", "20", "--speed-limit-mps", "1.0", "--clearance-m", "40")
        self.assertEqual(code, 0)
        self.assertIn("every band fits", output)

    def test_a_band_outgrowing_the_clearance_fails_the_command(self) -> None:
        code, output = self._run("--round-trip-ms", "40", "--speed-limit-mps", "2.0", "--clearance-m", "3.0")
        self.assertEqual(code, 1)
        self.assertIn("EXCEEDS CLEARANCE", output)

    def test_without_a_clearance_it_reports_rather_than_judges(self) -> None:
        code, _ = self._run("--round-trip-ms", "500", "--speed-limit-mps", "12", "--morphology", "air")
        self.assertEqual(code, 0)

    def test_json_output_carries_the_policy_and_every_band(self) -> None:
        _, output = self._run("--morphology", "air", "--speed-limit-mps", "12", "--json")
        payload = json.loads(output)
        self.assertEqual(payload["platform"]["morphology"], "air")
        self.assertAlmostEqual(payload["policy"]["coverage_k"], 5.5376, places=4)
        self.assertEqual(len(payload["bands"]), 6)
        self.assertEqual([row["age_ms"] for row in payload["bands"]], sorted(row["age_ms"] for row in payload["bands"]))

    def test_a_slower_link_demands_a_wider_band_for_the_same_platform(self) -> None:
        """The trade the command exists to make visible: a slower radio is
        a wider guard band is a wider aisle."""

        def first_band(round_trip_ms: str) -> float:
            _, output = self._run("--round-trip-ms", round_trip_ms, "--speed-limit-mps", "2.0", "--json")
            return json.loads(output)["bands"][0]["radius_m"]

        self.assertGreater(first_band("400"), first_band("20"))

    def test_an_impossible_risk_is_reported_as_a_protocol_error(self) -> None:
        from fasp_harness import cli

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(cli.main(["guard-budget", "--risk", "0"]), 2)

    def test_the_command_is_reachable_through_the_module_entry_point(self) -> None:
        from fasp_harness.__main__ import INDUSTRIAL_COMMANDS

        self.assertIn("guard-budget", INDUSTRIAL_COMMANDS)


if __name__ == "__main__":
    unittest.main()
