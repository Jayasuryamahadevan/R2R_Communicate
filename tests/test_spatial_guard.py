"""Guard bands: stated risk, the right bound winning, and cross-domain pairs.

These assert the properties an operator would be told the system has. Each
one is checkable by hand from the numbers in the failure message, which is
the point: a separation decision nobody can reconstruct afterwards is not
evidence, whatever it says.
"""

from __future__ import annotations

import math
import unittest

from fasp_harness.protocol.errors import FaspError
from fasp_harness.spatial.clock import TimeInterval
from fasp_harness.spatial.guard import (
    Envelope,
    GuardPolicy,
    Morphology,
    check_separation,
    coverage_factor,
    envelope_for,
)
from fasp_harness.spatial.linalg import identity, mat_scale
from fasp_harness.spatial.state import Aerial, ConstantVelocity, GroundVehicle, StateReport

TIGHT = mat_scale(identity(6), 0.01)


def _ugv(position: list[float], *, robot_id: str = "ugv-1", speed: float = 1.5, limit: float = 2.0, frame: str = "site") -> StateReport:
    return StateReport(robot_id, frame, position, [speed, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), GroundVehicle(), limit)


def _uav(position: list[float], *, robot_id: str = "uav-1", speed: float = 1.5) -> StateReport:
    return StateReport(robot_id, "site", position, [speed, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), Aerial(), 12.0)


class CoverageFactorTests(unittest.TestCase):
    def test_the_planar_closed_form_is_what_it_claims(self) -> None:
        self.assertAlmostEqual(coverage_factor(1e-6, 2), math.sqrt(-2.0 * math.log(1e-6)), places=12)
        self.assertAlmostEqual(coverage_factor(1e-6, 2), 5.2565, places=4)

    def test_three_dimensions_needs_a_larger_factor_than_two(self) -> None:
        """Using the planar figure for a volumetric problem quietly buys a
        worse guarantee than the one written down."""
        self.assertGreater(coverage_factor(1e-6, 3), coverage_factor(1e-6, 2))
        self.assertGreater(coverage_factor(1e-6, 2), coverage_factor(1e-6, 1))
        self.assertAlmostEqual(coverage_factor(1e-6, 3), 5.5376, places=4)

    def test_a_smaller_residual_risk_demands_a_wider_band(self) -> None:
        self.assertGreater(coverage_factor(1e-9, 3), coverage_factor(1e-6, 3))
        self.assertGreater(coverage_factor(1e-6, 3), coverage_factor(0.05, 3))

    def test_the_numerical_inversion_agrees_with_the_survival_function(self) -> None:
        from fasp_harness.spatial.guard import _chi_square_survival

        for alpha in (1e-9, 1e-6, 1e-3, 0.05, 0.5):
            for dimensions in (1, 2, 3):
                self.assertAlmostEqual(_chi_square_survival(coverage_factor(alpha, dimensions), dimensions), alpha, places=9)

    def test_an_impossible_risk_is_refused(self) -> None:
        for alpha in (0.0, 1.0, -0.5, 2.0):
            with self.assertRaises(FaspError):
                coverage_factor(alpha, 3)

    def test_an_unsupported_dimension_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            coverage_factor(1e-6, 7)


class EnvelopeSizingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = GuardPolicy()

    def test_the_band_grows_with_the_delay(self) -> None:
        radii = [envelope_for(_ugv([0.0, 0.0, 0.0]), self.policy, age, morphology=Morphology.GROUND).radius_m for age in (0.0, 500.0, 3_000.0)]
        self.assertEqual(radii, sorted(radii))

    def test_the_horizon_includes_the_delay_still_ahead_not_only_the_delay_suffered(self) -> None:
        """A band sized for the past is late by exactly the amount that matters."""
        envelope = envelope_for(_ugv([0.0, 0.0, 0.0]), GuardPolicy(latency_margin_s=0.2, control_period_s=0.1), 0.0, morphology=Morphology.GROUND)
        self.assertAlmostEqual(envelope.horizon_s, 0.3, places=9)

    def test_the_reachable_bound_takes_over_as_the_silence_lengthens(self) -> None:
        """The longer the silence, the less the motion model is evidence
        of anything, and the more the speed limit is all that is known."""
        report = _ugv([0.0, 0.0, 0.0], limit=3.0)
        late = envelope_for(report, self.policy, 8_000.0, morphology=Morphology.GROUND)
        self.assertGreater(late.reachable_half_extents_m[0], late.statistical_half_extents_m[0])

    def test_the_two_bounds_are_maximised_per_axis_never_summed(self) -> None:
        """Summing double-counts the motion since the report and trains
        operators to switch the guard off."""
        envelope = envelope_for(_ugv([0.0, 0.0, 0.0]), self.policy, 1_000.0, morphology=Morphology.GROUND, body_radius_m=0.4)
        for axis in range(3):
            expected = max(envelope.statistical_half_extents_m[axis], envelope.reachable_half_extents_m[axis]) + 0.4
            self.assertAlmostEqual(envelope.half_extents_m[axis], expected, places=12)

    def test_the_band_is_a_box_bounding_the_ellipsoid_not_its_enclosing_sphere(self) -> None:
        """k*sqrt(P_ii) is the exact support of the k-sigma ellipsoid along
        axis i, so the box is tight in every axis where a sphere is loose
        in all but the worst one."""
        report = _ugv([0.0, 0.0, 0.0], speed=0.001, limit=0.001)
        envelope = envelope_for(report, GuardPolicy(latency_margin_s=0.0, control_period_s=0.0), 0.0, morphology=Morphology.GROUND)
        propagated = report.propagated_to(0.0)
        coverage = coverage_factor(1e-6, 3)
        for axis in range(3):
            self.assertAlmostEqual(
                envelope.statistical_half_extents_m[axis],
                coverage * math.sqrt(propagated.covariance[axis][axis]),
                places=9,
            )
        # Strictly tighter than the sphere it replaced in at least one axis.
        self.assertLess(min(envelope.statistical_half_extents_m), max(envelope.statistical_half_extents_m))

    def test_a_ground_vehicle_cannot_reach_upwards_at_its_ground_speed(self) -> None:
        """The failure that put the old spherical band through the floor.

        Treating reachability as isotropic makes a 2 m/s AMR look able to
        climb at 2 m/s, inflating its band vertically by metres and
        conflicting it with aircraft it can never touch.
        """
        envelope = envelope_for(_ugv([0.0, 0.0, 0.0], limit=2.0), self.policy, 2_000.0, morphology=Morphology.GROUND)
        self.assertLess(envelope.half_extents_m[2], envelope.half_extents_m[0] / 2.0)
        self.assertAlmostEqual(envelope.half_extents_m[0], envelope.half_extents_m[1], places=9)

    def test_an_aerial_platform_reaches_vertically_but_climbs_slower_than_it_flies(self) -> None:
        envelope = envelope_for(_uav([0.0, 0.0, 5.0]), self.policy, 2_000.0, morphology=Morphology.AIR)
        self.assertLess(envelope.half_extents_m[2], envelope.half_extents_m[0])
        self.assertGreater(envelope.half_extents_m[2], envelope.half_extents_m[0] / 4.0)

    def test_a_faster_platform_needs_a_wider_band_for_the_same_silence(self) -> None:
        slow = envelope_for(_ugv([0.0, 0.0, 0.0], speed=0.5, limit=1.0), self.policy, 2_000.0, morphology=Morphology.GROUND)
        fast = envelope_for(_ugv([0.0, 0.0, 0.0], speed=0.5, limit=6.0), self.policy, 2_000.0, morphology=Morphology.GROUND)
        self.assertGreater(fast.half_extents_m[0], slow.half_extents_m[0])

    def test_the_body_radius_is_added_because_machines_are_not_points(self) -> None:
        bare = envelope_for(_ugv([0.0, 0.0, 0.0]), self.policy, 0.0, morphology=Morphology.GROUND)
        bulky = envelope_for(_ugv([0.0, 0.0, 0.0]), self.policy, 0.0, morphology=Morphology.GROUND, body_radius_m=0.75)
        for axis in range(3):
            self.assertAlmostEqual(bulky.half_extents_m[axis] - bare.half_extents_m[axis], 0.75, places=12)

    def test_a_report_past_its_model_horizon_is_flagged_on_the_envelope(self) -> None:
        envelope = envelope_for(_uav([0.0, 0.0, 5.0]), self.policy, 9_000.0, morphology=Morphology.AIR)
        self.assertTrue(envelope.beyond_model)

    def test_a_negative_body_radius_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            envelope_for(_ugv([0.0, 0.0, 0.0]), self.policy, 0.0, morphology=Morphology.GROUND, body_radius_m=-1.0)

    def test_the_stated_risk_travels_with_the_envelope(self) -> None:
        envelope = envelope_for(_ugv([0.0, 0.0, 0.0]), GuardPolicy(risk_alpha=1e-9), 0.0, morphology=Morphology.GROUND)
        self.assertEqual(envelope.risk_alpha, 1e-9)
        self.assertIn("risk_alpha", envelope.to_dict())


class SeparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = GuardPolicy()

    def _envelope(self, report: StateReport, morphology: Morphology, now_ms: float = 0.0, body: float = 0.4) -> Envelope:
        return envelope_for(report, self.policy, now_ms, morphology=morphology, body_radius_m=body)

    def test_a_drone_at_altitude_does_not_conflict_with_a_robot_below_it(self) -> None:
        """Plain 3D geometry gets the air/ground case right on its own --
        no special casing needed while the altitude separation holds."""
        verdict = check_separation(
            self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
            self._envelope(_uav([3.0, 0.0, 10.0]), Morphology.AIR),
        )
        self.assertTrue(verdict.clear)
        self.assertGreater(verdict.margin_m, 0.0)

    def test_the_same_pair_conflicts_once_the_drone_descends_to_land(self) -> None:
        verdict = check_separation(
            self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
            self._envelope(_uav([0.5, 0.0, 0.6], speed=0.2), Morphology.AIR),
        )
        self.assertFalse(verdict.clear)
        self.assertLess(verdict.margin_m, 0.0)

    def test_air_and_subsurface_are_cleared_by_the_medium_not_by_geometry(self) -> None:
        """Directly above one another and still separated, because the
        water column is between them."""
        auv = StateReport("auv-1", "site", [0.0, 0.0, -5.0], [0.0, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), ConstantVelocity(), 2.0)
        verdict = check_separation(self._envelope(_uav([0.0, 0.0, 20.0]), Morphology.AIR), self._envelope(auv, Morphology.SUBSURFACE))
        self.assertTrue(verdict.clear)
        self.assertIn("separated by the medium", verdict.reason)

    def test_surface_and_subsurface_do_share_a_volume_and_are_checked(self) -> None:
        """A hull and the submersible beneath it are not separated by the
        medium; they are in it together."""
        vessel = StateReport("usv-1", "site", [0.0, 0.0, 0.0], [0.0, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), ConstantVelocity(), 3.0)
        auv = StateReport("auv-1", "site", [0.2, 0.0, -0.5], [0.0, 0.0, 0.0], TIGHT, TimeInterval(0.0, 5.0), ConstantVelocity(), 2.0)
        verdict = check_separation(self._envelope(vessel, Morphology.SURFACE), self._envelope(auv, Morphology.SUBSURFACE))
        self.assertFalse(verdict.clear)

    def test_two_ground_robots_far_apart_are_clear(self) -> None:
        verdict = check_separation(
            self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
            self._envelope(_ugv([40.0, 0.0, 0.0], robot_id="ugv-2"), Morphology.GROUND),
        )
        self.assertTrue(verdict.clear)

    def test_a_long_silence_turns_a_clear_pair_into_a_conflict(self) -> None:
        """Nothing moved. The system merely stopped being able to prove
        that nothing moved, which is the behaviour a guard band is for."""
        first, second = _ugv([0.0, 0.0, 0.0]), _ugv([8.0, 0.0, 0.0], robot_id="ugv-2")
        self.assertTrue(check_separation(self._envelope(first, Morphology.GROUND), self._envelope(second, Morphology.GROUND)).clear)
        stale = check_separation(
            self._envelope(first, Morphology.GROUND, now_ms=6_000.0),
            self._envelope(second, Morphology.GROUND, now_ms=6_000.0),
        )
        self.assertFalse(stale.clear)

    def test_comparing_across_frames_is_refused(self) -> None:
        """Two positions in different frames are two different claims about
        the world. Comparing them as commensurable is the most dangerous
        thing this package could silently do."""
        with self.assertRaises(FaspError):
            check_separation(
                self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
                self._envelope(_ugv([1.0, 0.0, 0.0], robot_id="ugv-2", frame="uav/enu"), Morphology.GROUND),
            )

    def test_a_robot_is_not_checked_against_itself(self) -> None:
        envelope = self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND)
        with self.assertRaises(FaspError):
            check_separation(envelope, envelope)

    def test_the_verdict_carries_every_number_that_produced_it(self) -> None:
        first, second = _ugv([0.0, 0.0, 0.0]), _ugv([3.0, 0.0, 0.0], robot_id="ugv-2")
        verdict = check_separation(self._envelope(first, Morphology.GROUND), self._envelope(second, Morphology.GROUND))
        payload = verdict.to_dict()
        self.assertEqual(payload["margin_m"], max(payload["axis_margins_m"]))
        self.assertAlmostEqual(
            payload["axis_margins_m"][0],
            3.0 - verdict.first.half_extents_m[0] - verdict.second.half_extents_m[0],
            places=12,
        )
        self.assertEqual(payload["first"]["robot_id"], "ugv-1")

    def test_the_verdict_names_the_axis_that_proves_separation(self) -> None:
        """"Cleared by 18 m of altitude" and "cleared by 0.2 m laterally"
        are different operational situations, and a scalar margin cannot
        tell them apart."""
        vertical = check_separation(
            self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
            self._envelope(_uav([0.0, 0.0, 30.0]), Morphology.AIR),
        )
        self.assertEqual(vertical.separating_axis, "up")
        lateral = check_separation(
            self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
            self._envelope(_ugv([40.0, 0.0, 0.0], robot_id="ugv-2"), Morphology.GROUND),
        )
        self.assertEqual(lateral.separating_axis, "east")

    def test_an_overlapping_pair_names_no_separating_axis(self) -> None:
        verdict = check_separation(
            self._envelope(_ugv([0.0, 0.0, 0.0]), Morphology.GROUND),
            self._envelope(_ugv([0.5, 0.0, 0.0], robot_id="ugv-2"), Morphology.GROUND),
        )
        self.assertFalse(verdict.clear)
        self.assertIsNone(verdict.separating_axis)


if __name__ == "__main__":
    unittest.main()
