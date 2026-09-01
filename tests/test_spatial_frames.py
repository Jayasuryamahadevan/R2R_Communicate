"""Frame alignment: Kabsch fits, covariance that composes, links that decay.

The failures these guard against all look like success. A reflection is a
matrix. A collinear fit returns a rotation. A ten-minute-old SLAM
alignment still deserialises. Each test names the specific way the wrong
answer would have gone unnoticed.
"""

from __future__ import annotations

import math
import unittest

from fasp_harness.protocol.errors import FaspError
from fasp_harness.spatial.clock import TimeInterval
from fasp_harness.spatial.frames import (
    DriftRate,
    FrameGraph,
    FrameLink,
    Rigid3,
    align_frames,
    skew,
)
from fasp_harness.spatial.linalg import det3, identity, matmul, transpose

WELL_SPREAD = [[0.0, 0.0, 0.0], [3.0, 0.0, 0.0], [0.0, 4.0, 0.0], [1.0, 1.0, 2.0], [2.0, 3.0, 1.0]]


def _yaw(degrees: float) -> list[list[float]]:
    angle = math.radians(degrees)
    return [[math.cos(angle), -math.sin(angle), 0.0], [math.sin(angle), math.cos(angle), 0.0], [0.0, 0.0, 1.0]]


def _now() -> TimeInterval:
    return TimeInterval(0.0, 5.0)


class Rigid3Tests(unittest.TestCase):
    def test_inverse_undoes_the_transform(self) -> None:
        transform = Rigid3(_yaw(35.0), [4.0, -2.0, 0.5])
        point = [1.5, -0.5, 2.0]
        recovered = transform.inverse().apply(transform.apply(point))
        self.assertLess(max(abs(a - b) for a, b in zip(recovered, point, strict=True)), 1e-12)

    def test_composition_is_apply_other_then_self(self) -> None:
        first = Rigid3(_yaw(20.0), [1.0, 0.0, 0.0])
        second = Rigid3(_yaw(-50.0), [0.0, 2.0, -1.0])
        point = [0.7, 1.3, -0.2]
        self.assertLess(
            max(abs(a - b) for a, b in zip(first.compose(second).apply(point), first.apply(second.apply(point)), strict=True)),
            1e-12,
        )

    def test_a_matrix_that_is_not_a_rotation_is_refused_not_projected(self) -> None:
        """A peer can put any nine floats on the wire. Silently projecting
        them onto SO(3) would accept both a broken sender and a probing one."""
        with self.assertRaises(FaspError):
            Rigid3([[1.0, 0.0, 0.0], [0.0, 2.0, 0.0], [0.0, 0.0, 1.0]], [0.0, 0.0, 0.0])

    def test_a_reflection_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            Rigid3([[-1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]], [0.0, 0.0, 0.0])

    def test_adjoint_has_the_expected_block_structure(self) -> None:
        transform = Rigid3(_yaw(15.0), [2.0, 1.0, -3.0])
        adjoint = transform.adjoint()
        self.assertEqual([row[:3] for row in adjoint[3:]], [[0.0] * 3] * 3)
        self.assertEqual([row[:3] for row in adjoint[:3]], transform.rotation)
        self.assertEqual([row[3:] for row in adjoint[3:]], transform.rotation)
        self.assertEqual([row[3:] for row in adjoint[:3]], matmul(skew(transform.translation), transform.rotation))

    def test_round_trips_through_a_mapping(self) -> None:
        transform = Rigid3(_yaw(35.0), [4.0, -2.0, 0.5])
        self.assertEqual(Rigid3.from_mapping(transform.to_dict()), transform)


class AlignFramesTests(unittest.TestCase):
    def test_recovers_a_known_transform_exactly_from_clean_correspondences(self) -> None:
        truth = Rigid3(_yaw(35.0), [4.0, -2.0, 0.5])
        link = align_frames(
            WELL_SPREAD,
            [truth.apply(point) for point in WELL_SPREAD],
            source_frame="uav/enu",
            target_frame="ugv/map",
            observed_at=_now(),
        )
        self.assertLess(max(abs(a - b) for row_a, row_b in zip(link.transform.rotation, truth.rotation, strict=True) for a, b in zip(row_a, row_b, strict=True)), 1e-9)
        self.assertLess(max(abs(a - b) for a, b in zip(link.transform.translation, truth.translation, strict=True)), 1e-9)
        self.assertAlmostEqual(link.residual_rms_m, 0.0, places=9)

    def test_the_fitted_rotation_is_a_rotation_not_a_reflection(self) -> None:
        """Kabsch without the determinant correction happily returns a
        reflection when noise makes one fit marginally better. It is still
        an orthonormal matrix, so nothing downstream would notice."""
        mirrored = [[-point[0], point[1], point[2]] for point in WELL_SPREAD]
        link = align_frames(WELL_SPREAD, mirrored, source_frame="a", target_frame="b", observed_at=_now())
        self.assertAlmostEqual(det3(link.transform.rotation), 1.0, places=9)
        self.assertLess(max(abs(value) for row in matmul(transpose(link.transform.rotation), link.transform.rotation) for value in row), 1.0 + 1e-9)

    def test_collinear_correspondences_are_refused(self) -> None:
        """Three markers along a corridor wall. Rotation about that line is
        unobservable, and Kabsch still returns a number for it."""
        line = [[0.0, 0.0, 0.0], [1.0, 0.0, 0.0], [2.0, 0.0, 0.0], [3.0, 0.0, 0.0]]
        with self.assertRaises(FaspError):
            align_frames(line, line, source_frame="a", target_frame="b", observed_at=_now())

    def test_coincident_correspondences_are_refused(self) -> None:
        stack = [[1.0, 1.0, 1.0]] * 4
        with self.assertRaises(FaspError):
            align_frames(stack, stack, source_frame="a", target_frame="b", observed_at=_now())

    def test_too_few_correspondences_are_refused(self) -> None:
        with self.assertRaises(FaspError):
            align_frames(WELL_SPREAD[:2], WELL_SPREAD[:2], source_frame="a", target_frame="b", observed_at=_now())

    def test_mismatched_point_counts_are_refused(self) -> None:
        with self.assertRaises(FaspError):
            align_frames(WELL_SPREAD, WELL_SPREAD[:3], source_frame="a", target_frame="b", observed_at=_now())

    def test_noisier_correspondences_produce_a_wider_covariance(self) -> None:
        """The property that makes the covariance worth carrying at all."""
        truth = Rigid3(_yaw(10.0), [1.0, 1.0, 0.0])
        clean = [truth.apply(point) for point in WELL_SPREAD]
        noisy = [[value + offset for value, offset in zip(point, (0.05, -0.04, 0.03), strict=True)] for point in clean]
        tight = align_frames(WELL_SPREAD, clean, source_frame="a", target_frame="b", observed_at=_now(), measurement_sigma_m=0.01)
        loose = align_frames(WELL_SPREAD, noisy, source_frame="a", target_frame="b", observed_at=_now(), measurement_sigma_m=0.30)
        self.assertGreater(loose.position_sigma_m(), tight.position_sigma_m())

    def test_an_exact_fit_does_not_yield_a_covariance_of_zero(self) -> None:
        """Three clean points fit perfectly. That is evidence of few points,
        not of a perfect sensor, and a zero covariance becomes a guard band
        of nothing two layers up."""
        link = align_frames(WELL_SPREAD[:3], WELL_SPREAD[:3], source_frame="a", target_frame="b", observed_at=_now())
        self.assertGreater(link.position_sigma_m(), 0.0)

    def test_method_selects_a_drift_rate_by_default(self) -> None:
        surveyed = align_frames(WELL_SPREAD, WELL_SPREAD, source_frame="a", target_frame="b", observed_at=_now(), method="surveyed")
        odometry = align_frames(WELL_SPREAD, WELL_SPREAD, source_frame="a", target_frame="b", observed_at=_now(), method="odometry")
        self.assertEqual(surveyed.drift.translation_m_per_s, 0.0)
        self.assertGreater(odometry.drift.translation_m_per_s, 0.0)


class FrameLinkAgeingTests(unittest.TestCase):
    def _link(self, method: str) -> FrameLink:
        return align_frames(WELL_SPREAD, WELL_SPREAD, source_frame="ugv/map", target_frame="site", observed_at=_now(), method=method)

    def test_a_drifting_link_widens_with_age(self) -> None:
        """The failure this exists to prevent: a SLAM-derived alignment that
        was true ten minutes ago and is quietly still being trusted."""
        link = self._link("visual")
        fresh = link.position_sigma_m()
        stale = link.at(600_000.0).position_sigma_m()
        self.assertGreater(stale, 25.0)
        self.assertGreater(stale, fresh * 1000.0)

    def test_a_surveyed_link_does_not_decay(self) -> None:
        link = self._link("surveyed")
        self.assertAlmostEqual(link.at(600_000.0).position_sigma_m(), link.position_sigma_m(), places=12)

    def test_age_is_measured_from_the_latest_bound_so_a_bad_clock_never_inflates_it(self) -> None:
        link = FrameLink("a", "b", Rigid3.identity(), identity(6), "visual", TimeInterval(0.0, 1_000.0), DriftRate(1.0, 0.0))
        self.assertEqual(link.age_s(1_000.0), 0.0)
        self.assertAlmostEqual(link.age_s(2_000.0), 1.0, places=9)

    def test_ageing_a_link_that_is_not_yet_stale_returns_it_unchanged(self) -> None:
        link = self._link("visual")
        self.assertIs(link.at(-10_000.0), link)

    def test_inverse_is_an_involution_and_moves_the_covariance(self) -> None:
        link = align_frames(
            WELL_SPREAD,
            [Rigid3(_yaw(35.0), [4.0, -2.0, 0.5]).apply(point) for point in WELL_SPREAD],
            source_frame="a",
            target_frame="b",
            observed_at=_now(),
        )
        round_tripped = link.inverse().inverse()
        self.assertEqual(link.inverse().source_frame, "b")
        self.assertLess(max(abs(a - b) for a, b in zip(round_tripped.transform.translation, link.transform.translation, strict=True)), 1e-9)

    def test_a_non_psd_covariance_is_refused_on_construction(self) -> None:
        broken = identity(6)
        broken[0][0] = -1.0
        with self.assertRaises(FaspError):
            FrameLink("a", "b", Rigid3.identity(), broken, "uwb", _now())

    def test_a_link_cannot_join_a_frame_to_itself(self) -> None:
        with self.assertRaises(FaspError):
            FrameLink("a", "a", Rigid3.identity(), identity(6), "uwb", _now())

    def test_round_trips_through_a_mapping(self) -> None:
        link = self._link("uwb")
        restored = FrameLink.from_mapping(link.to_dict())
        self.assertEqual(restored.source_frame, link.source_frame)
        self.assertEqual(restored.method, link.method)
        self.assertAlmostEqual(restored.position_sigma_m(), link.position_sigma_m(), places=12)

    def test_a_malformed_payload_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            FrameLink.from_mapping({"source_frame": "a"})


class FrameGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = FrameGraph()
        self.first = align_frames(
            WELL_SPREAD,
            [Rigid3(_yaw(35.0), [4.0, -2.0, 0.5]).apply(point) for point in WELL_SPREAD],
            source_frame="uav/enu",
            target_frame="ugv/map",
            observed_at=_now(),
            method="uwb",
        )
        self.second = align_frames(
            WELL_SPREAD,
            [[point[0] + 10.0, point[1], point[2]] for point in WELL_SPREAD],
            source_frame="ugv/map",
            target_frame="site",
            observed_at=_now(),
            method="visual",
        )
        self.graph.add(self.first)
        self.graph.add(self.second)

    def test_composes_a_chain_the_graph_was_never_given_directly(self) -> None:
        composed = self.graph.lookup("uav/enu", "site")
        self.assertEqual((composed.source_frame, composed.target_frame), ("uav/enu", "site"))
        expected = self.first.transform.compose(self.second.transform)
        self.assertLess(max(abs(a - b) for a, b in zip(composed.transform.translation, expected.translation, strict=True)), 1e-9)

    def test_two_hops_are_strictly_less_certain_than_one(self) -> None:
        """What makes a long chain visibly untrustworthy rather than
        invisibly so."""
        self.assertGreater(self.graph.lookup("uav/enu", "site").position_sigma_m(), self.first.position_sigma_m())

    def test_adding_a_link_makes_the_reverse_direction_available(self) -> None:
        self.assertTrue(self.graph.has_direct("ugv/map", "uav/enu"))
        self.assertLess(self.graph.lookup("site", "uav/enu").position_sigma_m(), 1.0)

    def test_a_chain_is_only_as_current_as_its_stalest_link(self) -> None:
        aged = self.graph.lookup("uav/enu", "site", now_ms=600_000.0)
        self.assertGreater(aged.position_sigma_m(), 25.0)

    def test_composed_drift_is_governed_by_the_weakest_member(self) -> None:
        composed = self.graph.lookup("uav/enu", "site")
        self.assertEqual(composed.drift.translation_m_per_s, self.second.drift.translation_m_per_s)

    def test_an_unreachable_frame_is_an_error_not_an_identity(self) -> None:
        with self.assertRaises(FaspError):
            self.graph.lookup("uav/enu", "warehouse/dock")

    def test_composing_links_that_do_not_meet_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            self.first.compose(self.first)

    def test_the_shortest_chain_is_preferred(self) -> None:
        direct = align_frames(
            WELL_SPREAD,
            [[point[0] + 1.0, point[1] + 1.0, point[2]] for point in WELL_SPREAD],
            source_frame="uav/enu",
            target_frame="site",
            observed_at=_now(),
            method="surveyed",
        )
        self.graph.add(direct)
        self.assertEqual(self.graph.path("uav/enu", "site"), ["uav/enu", "site"])
        self.assertAlmostEqual(self.graph.lookup("uav/enu", "site").position_sigma_m(), direct.position_sigma_m(), places=12)


if __name__ == "__main__":
    unittest.main()
