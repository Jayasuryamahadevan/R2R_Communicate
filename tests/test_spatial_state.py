"""State reports: propagation, domain-specific noise, and frame composition.

The recurring theme is that every one of these failures produces a number
that looks fine. A prediction ignoring clock slop is a position. A drone
modelled with a ground robot's process noise is a tight ellipse. A peer's
pose transformed without the frame link's covariance is a confident point
in the wrong place.
"""

from __future__ import annotations

import math
import unittest

from fasp_harness.protocol.errors import FaspError
from fasp_harness.spatial.clock import TimeInterval
from fasp_harness.spatial.frames import DriftRate, FrameLink, Rigid3
from fasp_harness.spatial.linalg import identity, mat_scale
from fasp_harness.spatial.state import (
    Aerial,
    ConstantVelocity,
    GroundVehicle,
    StateReport,
    model_from_mapping,
)

TIGHT = mat_scale(identity(6), 0.01)


def _report(**overrides: object) -> StateReport:
    defaults: dict[str, object] = {
        "robot_id": "ugv-1",
        "frame_id": "site",
        "position_m": [0.0, 0.0, 0.0],
        "velocity_mps": [1.5, 0.0, 0.0],
        "covariance": TIGHT,
        "stamp": TimeInterval(0.0, 5.0),
        "motion": GroundVehicle(),
        "speed_limit_mps": 2.0,
    }
    defaults.update(overrides)
    return StateReport(**defaults)  # type: ignore[arg-type]


class ValidationTests(unittest.TestCase):
    def test_a_covariance_that_is_not_one_is_refused(self) -> None:
        """Thirty-six arbitrary floats stop here, before they reach a guard band."""
        broken = mat_scale(identity(6), 0.01)
        broken[0][0] = -1.0
        with self.assertRaises(FaspError):
            _report(covariance=broken)

    def test_an_asymmetric_covariance_is_refused(self) -> None:
        broken = mat_scale(identity(6), 0.01)
        broken[0][1] = 0.5
        with self.assertRaises(FaspError):
            _report(covariance=broken)

    def test_velocity_exceeding_the_declared_speed_limit_is_refused(self) -> None:
        """Either the limit or the velocity is a lie, and the guard band
        depends on the limit being the true bound."""
        with self.assertRaises(FaspError):
            _report(velocity_mps=[9.0, 0.0, 0.0], speed_limit_mps=2.0)

    def test_non_finite_position_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            _report(position_m=[float("nan"), 0.0, 0.0])

    def test_round_trips_through_a_mapping(self) -> None:
        report = _report(motion=Aerial())
        restored = StateReport.from_mapping(report.to_dict())
        self.assertEqual(restored.robot_id, report.robot_id)
        self.assertEqual(restored.motion.to_dict(), report.motion.to_dict())
        self.assertAlmostEqual(restored.position_sigma_m(), report.position_sigma_m(), places=12)

    def test_a_malformed_payload_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            StateReport.from_mapping({"robot_id": "x"})

    def test_an_unknown_motion_model_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            model_from_mapping({"kind": "teleportation"})


class PropagationTests(unittest.TestCase):
    def test_uncertainty_grows_with_the_delay(self) -> None:
        report = _report()
        sigmas = [report.propagated_to(delay).position_sigma_m() for delay in (0.0, 200.0, 1_000.0, 5_000.0)]
        self.assertEqual(sigmas, sorted(sigmas))

    def test_the_mean_advances_along_the_reported_velocity(self) -> None:
        moved = _report().propagated_to(2_000.0)
        self.assertAlmostEqual(moved.position_m[0], 3.0, places=9)
        self.assertAlmostEqual(moved.position_m[1], 0.0, places=9)

    def test_clock_slop_becomes_position_uncertainty_along_the_direction_of_travel(self) -> None:
        """The seam between clock.py and this module.

        Not knowing *when* to within 200 ms, at 1.5 m/s, is not knowing
        *where* to within 0.3 m -- however good the sensor was. A system
        that propagates covariance perfectly and omits this reports a
        confident, wrong position every time the clocks drift.
        """
        tight = _report(stamp=TimeInterval(0.0, 0.0)).propagated_to(0.0)
        sloppy = _report(stamp=TimeInterval(0.0, 200.0)).propagated_to(0.0)
        self.assertAlmostEqual(sloppy.covariance[0][0] - tight.covariance[0][0], (1.5 * 0.2) ** 2, places=9)
        # And only along travel: the robot moves in x, so y is untouched.
        self.assertAlmostEqual(sloppy.covariance[1][1], tight.covariance[1][1], places=12)

    def test_a_stationary_robot_gains_no_timing_smear(self) -> None:
        """v * epsilon is zero when v is. A parked robot with a terrible
        clock is still exactly where it was."""
        parked = _report(velocity_mps=[0.0, 0.0, 0.0], stamp=TimeInterval(0.0, 5_000.0))
        reference = _report(velocity_mps=[0.0, 0.0, 0.0], stamp=TimeInterval(0.0, 0.0))
        self.assertAlmostEqual(parked.propagated_to(0.0).covariance[0][0], reference.propagated_to(0.0).covariance[0][0], places=12)

    def test_a_report_stamped_in_the_future_is_not_retrodicted(self) -> None:
        """A clock disagreement is not a robot that has yet to move. The
        mean holds still; the uncertainty still grows."""
        backwards = _report().propagated_to(-3_000.0)
        self.assertAlmostEqual(backwards.position_m[0], 0.0, places=9)
        self.assertGreater(backwards.position_sigma_m(), _report().position_sigma_m())

    def test_velocity_uncertainty_feeds_position_uncertainty(self) -> None:
        """The transition term. A robot whose speed is poorly known is
        somewhere poorly known, increasingly so."""
        loose_velocity = mat_scale(identity(6), 0.01)
        for axis in range(3, 6):
            loose_velocity[axis][axis] = 1.0
        wide = _report(covariance=loose_velocity).propagated_to(2_000.0)
        narrow = _report().propagated_to(2_000.0)
        self.assertGreater(wide.position_sigma_m(), narrow.position_sigma_m())

    def test_the_cross_terms_are_not_dropped(self) -> None:
        """Position/velocity covariance encodes that a robot going faster
        than believed is also further along than believed. Dropping it
        understates position growth by roughly four."""
        propagated = _report().propagated_to(1_000.0)
        self.assertGreater(abs(propagated.covariance[0][3]), 0.0)


class MotionModelTests(unittest.TestCase):
    def test_an_aerial_platform_decays_much_faster_than_a_ground_one(self) -> None:
        """Wind gusts against wheel slip. Modelling both with one blob is
        wrong in opposite directions."""
        ground = _report(motion=GroundVehicle()).propagated_to(5_000.0).position_sigma_m()
        aerial = _report(motion=Aerial(), speed_limit_mps=12.0).propagated_to(5_000.0).position_sigma_m()
        self.assertGreater(aerial, ground * 4.0)

    def test_ground_uncertainty_is_anisotropic_and_grows_with_speed(self) -> None:
        """Heading error times distance driven is cross-track error, so the
        sideways/forwards ratio must rise with speed -- a parked robot has
        no heading-induced lateral error at all."""

        def anisotropy(speed: float) -> float:
            covariance = _report(velocity_mps=[speed, 0.0, 0.0], speed_limit_mps=max(speed, 0.1)).propagated_to(5_000.0).covariance
            return covariance[1][1] / covariance[0][0]

        self.assertAlmostEqual(anisotropy(0.0), 1.0, places=6)
        self.assertGreater(anisotropy(2.0), anisotropy(0.0))
        self.assertGreater(anisotropy(6.0), anisotropy(2.0))

    def test_an_aerial_platform_is_isotropic_in_the_horizontal_plane(self) -> None:
        """Gusts arrive from any bearing, so process noise has no favoured
        axis. Asserted on a zero-width stamp so the only remaining source
        of anisotropy -- timing smear along travel -- is excluded."""
        exact_clock = _report(motion=Aerial(), velocity_mps=[8.0, 0.0, 0.0], speed_limit_mps=12.0, stamp=TimeInterval(0.0, 0.0))
        covariance = exact_clock.propagated_to(2_000.0).covariance
        self.assertAlmostEqual(covariance[0][0], covariance[1][1], places=9)

    def test_timing_smear_is_the_only_anisotropy_an_aerial_report_has(self) -> None:
        """The complement of the test above: with a real clock, the excess
        along the direction of travel is exactly (v * epsilon)^2."""
        covariance = _report(motion=Aerial(), velocity_mps=[8.0, 0.0, 0.0], speed_limit_mps=12.0, stamp=TimeInterval(0.0, 5.0)).propagated_to(2_000.0).covariance
        self.assertAlmostEqual(covariance[0][0] - covariance[1][1], (8.0 * 0.005) ** 2, places=9)

    def test_beyond_the_model_horizon_is_flagged_rather_than_rejected(self) -> None:
        aerial = _report(motion=Aerial(model_horizon_s=3.0), speed_limit_mps=12.0)
        self.assertFalse(aerial.beyond_model(2_000.0))
        self.assertTrue(aerial.beyond_model(5_000.0))
        self.assertGreater(aerial.propagated_to(5_000.0).position_sigma_m(), 0.0)

    def test_constant_velocity_is_available_as_a_neutral_default(self) -> None:
        self.assertGreater(_report(motion=ConstantVelocity()).propagated_to(1_000.0).position_sigma_m(), 0.0)


class FrameCompositionTests(unittest.TestCase):
    def _link(self, sigma: float, drift: DriftRate | None = None) -> FrameLink:
        return FrameLink(
            "site",
            "ugv/map",
            Rigid3(identity(3), [10.0, 0.0, 0.0]),
            mat_scale(identity(6), sigma**2),
            "uwb",
            TimeInterval(0.0, 0.0),
            drift or DriftRate(),
        )

    def test_the_position_moves_into_the_target_frame(self) -> None:
        moved = _report(position_m=[1.0, 2.0, 0.0]).in_frame(self._link(0.05))
        self.assertEqual(moved.frame_id, "ugv/map")
        self.assertAlmostEqual(moved.position_m[0], 11.0, places=9)

    def test_the_frame_links_own_error_is_added_not_discarded(self) -> None:
        """A robot with excellent onboard localisation is still a poor
        coordination partner across a badly estimated frame boundary."""
        own = _report().position_sigma_m()
        crossed = _report().in_frame(self._link(0.5)).position_sigma_m()
        self.assertGreater(crossed, own)
        self.assertGreater(crossed, 0.5)

    def test_a_worse_link_yields_a_worse_result(self) -> None:
        good = _report().in_frame(self._link(0.02)).position_sigma_m()
        bad = _report().in_frame(self._link(1.0)).position_sigma_m()
        self.assertGreater(bad, good)

    def test_frame_rotation_error_grows_with_the_lever_arm(self) -> None:
        """Angular error in the link becomes position error in proportion
        to how far the point is from the frame origin."""
        link = self._link(0.05)
        near = _report(position_m=[1.0, 0.0, 0.0]).in_frame(link).position_sigma_m()
        far = _report(position_m=[100.0, 0.0, 0.0]).in_frame(link).position_sigma_m()
        self.assertGreater(far, near)

    def test_a_stale_link_widens_the_result_when_a_time_is_supplied(self) -> None:
        link = self._link(0.05, DriftRate(0.05, 0.002))
        fresh = _report().in_frame(link, now_ms=0.0).position_sigma_m()
        stale = _report().in_frame(link, now_ms=60_000.0).position_sigma_m()
        self.assertGreater(stale, fresh * 10.0)

    def test_the_report_and_the_link_are_assumed_correlated_by_default(self) -> None:
        """Frame links are very often estimated *from* the observations of
        the robots they relate, so the peer's localisation error and the
        link error can be the same error seen twice."""
        link = self._link(0.3)
        cautious = _report().in_frame(link).position_sigma_m()
        asserted = _report().in_frame(link, correlated=False).position_sigma_m()
        self.assertGreater(cautious, asserted)

    def test_a_link_from_the_wrong_frame_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            _report(frame_id="uav/enu").in_frame(self._link(0.05))

    def test_velocity_is_rotated_into_the_target_frame(self) -> None:
        rotation = [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]]
        link = FrameLink(
            "site",
            "ugv/map",
            Rigid3(rotation, [0.0, 0.0, 0.0]),
            mat_scale(identity(6), 1e-6),
            "surveyed",
            TimeInterval(0.0, 0.0),
        )
        moved = _report(velocity_mps=[1.5, 0.0, 0.0]).in_frame(link)
        self.assertAlmostEqual(moved.velocity_mps[0], 0.0, places=9)
        self.assertAlmostEqual(moved.velocity_mps[1], 1.5, places=9)
        self.assertAlmostEqual(math.hypot(*moved.velocity_mps[:2]), 1.5, places=9)


if __name__ == "__main__":
    unittest.main()
