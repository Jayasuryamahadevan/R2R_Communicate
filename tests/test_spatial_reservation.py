"""Reservations that survive contact with hardware.

The exact overlap test -- same cell name, same millisecond range -- is the
right property for a ledger and the wrong one for two machines that
disagree about the time and do not know precisely where they are. These
tests pin down what the dilated version buys, and equally that a
reservation which asks for none of it behaves exactly as it always did.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.protocol.errors import FaspError
from fasp_harness.robotics import MAX_GUARD_MS, MAX_VOLUME_EXTENT_M, ReservationBook
from fasp_harness.spatial import (
    GroundVehicle,
    GuardPolicy,
    Morphology,
    StateReport,
    TimeInterval,
    envelope_for,
    reserve_occupancy,
    segment_from_envelope,
    segments_for_occupancy,
)
from fasp_harness.spatial.linalg import identity, mat_scale
from fasp_harness.storage.db import Database
from fasp_harness.storage.reservations_repo import ReservationsRepo

TIGHT = mat_scale(identity(6), 0.01)
NOW = 1_800_000_000_000


class ReservationFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.book = ReservationBook(ReservationsRepo(Database(Path(self.temp.name) / "fasp.db")))
        self.policy = GuardPolicy()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def report(self, robot_id: str, position: list[float], velocity: list[float] | None = None, *, clock_ms: float = 50.0) -> StateReport:
        import time

        return StateReport(
            robot_id,
            "site",
            position,
            velocity or [1.2, 0.0, 0.0],
            TIGHT,
            TimeInterval(int(time.time() * 1000), clock_ms),
            GroundVehicle(),
            1.5,
        )

    def reserve(self, robot_id: str, position: list[float], cell: str, *, window_ms: int = 3_000, **kwargs) -> dict:
        import time

        now = int(time.time() * 1000)
        return reserve_occupancy(
            self.book,
            robot_id,
            self.report(robot_id, position, **kwargs),
            self.policy,
            morphology=Morphology.GROUND,
            cell=cell,
            start_ms=now,
            end_ms=now + window_ms,
            body_radius_m=0.4,
        )


class BackwardCompatibilityTests(ReservationFixture):
    """A reservation that asks for no dilation must behave as it always did."""

    def test_a_plain_segment_is_still_granted_and_still_conflicts_on_the_cell(self) -> None:
        payload = {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 5_000}], "lease_ms": 10_000}
        self.assertEqual(self.book.request("ugv-1", payload)["type"], "reservation.grant")
        rejected = self.book.request("ugv-2", {"segments": [{"cell": "aisle-A", "start_ms": NOW + 1_000, "end_ms": NOW + 3_000}]})
        self.assertEqual(rejected["type"], "reservation.reject")
        self.assertEqual(rejected["basis"], "cell")

    def test_plain_segments_that_do_not_touch_are_both_granted(self) -> None:
        self.book.request("ugv-1", {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 1_000}]})
        second = self.book.request("ugv-2", {"segments": [{"cell": "aisle-A", "start_ms": NOW + 2_000, "end_ms": NOW + 3_000}]})
        self.assertEqual(second["type"], "reservation.grant")

    def test_a_segment_reports_the_requested_window_alongside_the_enforced_one(self) -> None:
        """An operator needs both: what was asked for, and the wider window
        the arbiter actually enforced on their behalf."""
        granted = self.book.request("ugv-1", {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 1_000, "guard_ms": 250}]})
        segment = granted["segments"][0]
        self.assertEqual((segment["start_ms"], segment["end_ms"]), (NOW, NOW + 1_000))
        self.assertEqual(segment["guard_ms"], 250)


class TemporalDilationTests(ReservationFixture):
    def test_two_segments_apart_on_paper_conflict_once_the_clocks_are_admitted(self) -> None:
        """The failure this exists for. Ten milliseconds of separation
        between owners whose clocks disagree by two hundred is not
        separation at all, and the exact ledger said it was."""
        self.book.request("ugv-1", {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 1_000, "guard_ms": 200}]})
        rejected = self.book.request("ugv-2", {"segments": [{"cell": "aisle-A", "start_ms": NOW + 1_010, "end_ms": NOW + 2_000, "guard_ms": 200}]})
        self.assertEqual(rejected["type"], "reservation.reject")

    def test_the_same_pair_is_granted_when_both_clocks_are_trustworthy(self) -> None:
        """The dilation is not blanket pessimism: a deployment with good
        clocks gets its tight packing back."""
        self.book.request("ugv-1", {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 1_000, "guard_ms": 1}]})
        granted = self.book.request("ugv-2", {"segments": [{"cell": "aisle-A", "start_ms": NOW + 1_010, "end_ms": NOW + 2_000, "guard_ms": 1}]})
        self.assertEqual(granted["type"], "reservation.grant")

    def test_dilation_is_mutual_so_one_bad_clock_is_enough_to_conflict(self) -> None:
        self.book.request("ugv-1", {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 1_000, "guard_ms": 0}]})
        rejected = self.book.request("ugv-2", {"segments": [{"cell": "aisle-A", "start_ms": NOW + 1_100, "end_ms": NOW + 2_000, "guard_ms": 400}]})
        self.assertEqual(rejected["type"], "reservation.reject")

    def test_the_lease_outlasts_the_widened_window_not_the_requested_one(self) -> None:
        """A reservation released while its guard band still excluded other
        traffic would be a hole in the arbitration.

        Uses a real clock rather than the module's fixed constant, because
        the lease is `min(now + lease_ms, widened_end + slack)` and only a
        realistic `now` exercises the second branch.
        """
        import time

        now = int(time.time() * 1000)
        payload = {"segments": [{"cell": "aisle-A", "start_ms": now, "end_ms": now + 1_000, "guard_ms": 5_000}], "lease_ms": 120_000}
        granted = self.book.request("ugv-1", payload)
        self.assertGreaterEqual(granted["lease_until_ms"], now + 1_000 + 5_000)

        without_guard = {"segments": [{"cell": "aisle-B", "start_ms": now, "end_ms": now + 1_000}], "lease_ms": 120_000}
        self.assertLess(self.book.request("ugv-2", without_guard)["lease_until_ms"], granted["lease_until_ms"])

    def test_an_abusive_guard_is_refused(self) -> None:
        """A robot claiming thirty seconds of clock doubt has a clock
        problem to fix, not a larger reservation to be granted."""
        with self.assertRaises(FaspError):
            self.book.request("ugv-1", {"segments": [{"cell": "aisle-A", "start_ms": NOW, "end_ms": NOW + 1_000, "guard_ms": MAX_GUARD_MS + 1}]})

    def test_a_negative_or_nonsense_guard_is_refused(self) -> None:
        for guard in (-1, "soon", True, float("nan")):
            with self.assertRaises(FaspError, msg=repr(guard)):
                self.book.request("ugv-1", {"segments": [{"cell": "x", "start_ms": NOW, "end_ms": NOW + 1_000, "guard_ms": guard}]})


class VolumeConflictTests(ReservationFixture):
    def test_robots_in_different_named_cells_still_conflict_physically(self) -> None:
        """The result that makes this worth building.

        A cell name is a convention two vendors must agree on first. A box
        in a named frame is not -- so two robots that share no cell
        vocabulary still cannot occupy the same air.
        """
        self.assertEqual(self.reserve("ugv-1", [0.0, 0.0, 0.0], "aisle-A")["type"], "reservation.grant")
        rejected = self.reserve("ugv-2", [6.0, 0.0, 0.0], "aisle-B")
        self.assertEqual(rejected["type"], "reservation.reject")
        self.assertEqual(rejected["basis"], "volume")

    def test_robots_genuinely_far_apart_are_both_granted(self) -> None:
        self.assertEqual(self.reserve("ugv-1", [0.0, 0.0, 0.0], "aisle-A")["type"], "reservation.grant")
        self.assertEqual(self.reserve("ugv-3", [80.0, 0.0, 0.0], "aisle-C")["type"], "reservation.grant")

    def test_a_conflict_says_whether_the_cell_map_or_the_geometry_caught_it(self) -> None:
        """An operator debugging a livelock needs to know which; they are
        different problems with different fixes."""
        self.reserve("ugv-1", [0.0, 0.0, 0.0], "aisle-A")
        self.assertEqual(self.reserve("ugv-2", [0.5, 0.0, 0.0], "aisle-A")["basis"], "cell")
        self.assertEqual(self.reserve("ugv-4", [4.0, 0.0, 0.0], "aisle-Z")["basis"], "volume")

    def test_a_volume_beyond_the_extent_cap_is_refused(self) -> None:
        oversized = {
            "cell": "aisle-A",
            "start_ms": NOW,
            "end_ms": NOW + 1_000,
            "volume": {"frame_id": "site", "minimum_m": [0.0, 0.0, 0.0], "maximum_m": [MAX_VOLUME_EXTENT_M + 1.0, 1.0, 1.0]},
        }
        with self.assertRaises(FaspError):
            self.book.request("ugv-1", {"segments": [oversized]})

    def test_a_degenerate_volume_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            self.book.request(
                "ugv-1",
                {"segments": [{"cell": "a", "start_ms": NOW, "end_ms": NOW + 1_000, "volume": {"frame_id": "site", "minimum_m": [0.0, 0.0, 0.0], "maximum_m": [0.0, 1.0, 1.0]}}]},
            )

    def test_a_volume_without_a_frame_is_refused(self) -> None:
        """Two boxes in unnamed frames are not comparable, and quietly
        treating them as though they were is the dangerous case."""
        with self.assertRaises(FaspError):
            self.book.request(
                "ugv-1",
                {"segments": [{"cell": "a", "start_ms": NOW, "end_ms": NOW + 1_000, "volume": {"minimum_m": [0.0, 0.0, 0.0], "maximum_m": [1.0, 1.0, 1.0]}}]},
            )

    def test_volumes_in_different_frames_do_not_conflict_with_each_other(self) -> None:
        def payload(frame: str, cell: str) -> dict:
            return {
                "segments": [
                    {
                        "cell": cell,
                        "start_ms": NOW,
                        "end_ms": NOW + 1_000,
                        "volume": {"frame_id": frame, "minimum_m": [0.0, 0.0, 0.0], "maximum_m": [1.0, 1.0, 1.0]},
                    }
                ]
            }

        self.book.request("ugv-1", payload("site", "a"))
        self.assertEqual(self.book.request("ugv-2", payload("other-site", "b"))["type"], "reservation.grant")


class OccupancySamplingTests(ReservationFixture):
    def test_the_swept_corridor_is_a_widening_cone_not_a_tube(self) -> None:
        """Exactly the right shape for something whose future position is
        progressively less certain."""
        import time

        now = int(time.time() * 1000)
        segments = segments_for_occupancy(
            self.report("ugv-1", [0.0, 0.0, 0.0]),
            self.policy,
            morphology=Morphology.GROUND,
            cell="aisle-A",
            start_ms=now,
            end_ms=now + 4_000,
            body_radius_m=0.4,
        )
        widths = [segment["volume"]["maximum_m"][0] - segment["volume"]["minimum_m"][0] for segment in segments]
        self.assertEqual(len(segments), 4)
        self.assertEqual(widths, sorted(widths))
        self.assertGreater(widths[-1], widths[0] * 2.0)

    def test_the_guard_is_the_clock_bound_plus_the_decision_margin(self) -> None:
        """The band and the reservation are the same number, not two
        numbers that drift apart."""
        import time

        now = int(time.time() * 1000)
        segments = segments_for_occupancy(
            self.report("ugv-1", [0.0, 0.0, 0.0], clock_ms=50.0),
            GuardPolicy(latency_margin_s=0.2, control_period_s=0.1),
            morphology=Morphology.GROUND,
            cell="aisle-A",
            start_ms=now,
            end_ms=now + 1_000,
        )
        self.assertEqual(segments[0]["guard_ms"], 350)

    def test_the_reserved_box_is_the_guard_band_itself(self) -> None:
        import time

        now = int(time.time() * 1000)
        report = self.report("ugv-1", [0.0, 0.0, 0.0])
        envelope = envelope_for(report, self.policy, now + 1_000, morphology=Morphology.GROUND, body_radius_m=0.4)
        segment = segment_from_envelope(envelope, start_ms=now, end_ms=now + 1_000, cell="aisle-A", guard_ms=0.0)
        self.assertEqual(segment["volume"]["minimum_m"], envelope.minimum_m())
        self.assertEqual(segment["volume"]["maximum_m"], envelope.maximum_m())

    def test_a_report_too_stale_to_reserve_against_is_refused_not_granted_enormously(self) -> None:
        """A minute of silence gives a robot a legitimate claim to a very
        large box. Granting it would let one stale peer reserve the site."""
        stale = StateReport("ugv-1", "site", [0.0, 0.0, 0.0], [1.2, 0.0, 0.0], TIGHT, TimeInterval(0.0, 50.0), GroundVehicle(), 1.5)
        with self.assertRaises(FaspError):
            segments_for_occupancy(
                stale,
                self.policy,
                morphology=Morphology.GROUND,
                cell="aisle-A",
                start_ms=NOW,
                end_ms=NOW + 1_000,
            )

    def test_an_inverted_window_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            segments_for_occupancy(
                self.report("ugv-1", [0.0, 0.0, 0.0]),
                self.policy,
                morphology=Morphology.GROUND,
                cell="a",
                start_ms=NOW + 1_000,
                end_ms=NOW,
            )

    def test_an_absurd_step_count_is_refused(self) -> None:
        import time

        now = int(time.time() * 1000)
        for steps in (0, 65):
            with self.assertRaises(FaspError, msg=str(steps)):
                segments_for_occupancy(
                    self.report("ugv-1", [0.0, 0.0, 0.0]),
                    self.policy,
                    morphology=Morphology.GROUND,
                    cell="a",
                    start_ms=now,
                    end_ms=now + 1_000,
                    steps=steps,
                )


if __name__ == "__main__":
    unittest.main()
