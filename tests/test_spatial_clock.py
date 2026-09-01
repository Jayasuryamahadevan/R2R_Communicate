"""Two-way time transfer: offset, bounded error, drift, and refusal to guess.

Every test here runs on constructed timestamps rather than a real clock, so
each one asserts about the estimator's arithmetic instead of about how
quiet the CI machine happened to be.
"""

from __future__ import annotations

import random
import unittest

from fasp_harness.protocol.errors import FaspError
from fasp_harness.spatial.clock import (
    COMMODITY_CRYSTAL_PPM,
    ClockTracker,
    Exchange,
    TimeInterval,
)


def _exchange(local_send: float, true_offset_ms: float, round_trip_ms: float, *, dwell_ms: float = 1.0, forward_share: float = 0.5) -> Exchange:
    """Build a physically consistent exchange with a known true offset."""
    forward = round_trip_ms * forward_share
    t2 = local_send + forward + true_offset_ms
    return Exchange(local_send, t2, t2 + dwell_ms, local_send + round_trip_ms + dwell_ms)


class TimeIntervalTests(unittest.TestCase):
    def test_endpoints_bracket_the_centre(self) -> None:
        interval = TimeInterval(1000.0, 25.0)
        self.assertEqual((interval.earliest_ms, interval.latest_ms), (975.0, 1025.0))

    def test_touching_intervals_are_not_treated_as_separated(self) -> None:
        """Two machines whose windows merely touch are not proven apart."""
        self.assertTrue(TimeInterval(100.0, 10.0).overlaps(TimeInterval(120.0, 10.0)))
        self.assertFalse(TimeInterval(100.0, 10.0).overlaps(TimeInterval(121.0, 10.0)))

    def test_a_negative_width_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            TimeInterval(0.0, -1.0)

    def test_round_trips_through_a_mapping(self) -> None:
        interval = TimeInterval(42.5, 3.25)
        self.assertEqual(TimeInterval.from_mapping(interval.to_dict()), interval)

    def test_a_mapping_missing_numbers_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            TimeInterval.from_mapping({"center_ms": "soon", "half_width_ms": 1.0})


class ExchangeTests(unittest.TestCase):
    def test_recovers_the_offset_when_the_path_is_symmetric(self) -> None:
        exchange = _exchange(0.0, true_offset_ms=1000.0, round_trip_ms=40.0)
        self.assertAlmostEqual(exchange.offset_ms, 1000.0, places=9)
        self.assertAlmostEqual(exchange.round_trip_ms, 40.0, places=9)

    def test_the_true_offset_stays_inside_the_bound_under_worst_case_asymmetry(self) -> None:
        """The one guarantee this arithmetic actually makes.

        theta is wrong whenever the path is asymmetric, but it is never
        wrong by more than delta/2 -- so the interval, unlike the point
        estimate, is always correct.
        """
        for share in (0.0, 0.1, 0.5, 0.9, 1.0):
            exchange = _exchange(0.0, true_offset_ms=500.0, round_trip_ms=80.0, forward_share=share)
            self.assertTrue(exchange.as_interval().contains(500.0), f"forward_share={share}")

    def test_dwell_time_is_removed_from_the_round_trip(self) -> None:
        """A responder that thinks for a second has not added a second of
        network distance, and must not widen the bound as though it had."""
        quick = _exchange(0.0, 0.0, round_trip_ms=30.0, dwell_ms=1.0)
        slow = _exchange(0.0, 0.0, round_trip_ms=30.0, dwell_ms=1000.0)
        self.assertAlmostEqual(quick.round_trip_ms, slow.round_trip_ms, places=9)

    def test_a_clock_step_during_the_exchange_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            Exchange(1000.0, 10.0, 11.0, 500.0)
        with self.assertRaises(FaspError):
            Exchange(0.0, 1000.0, 10.0, 50.0)

    def test_an_impossible_round_trip_is_refused(self) -> None:
        """Remote dwell longer than the whole local elapsed time."""
        with self.assertRaises(FaspError):
            Exchange(0.0, 0.0, 500.0, 100.0)

    def test_an_outage_length_round_trip_is_not_accepted_as_a_measurement(self) -> None:
        with self.assertRaises(FaspError):
            _exchange(0.0, 0.0, round_trip_ms=60_000.0)


class ClockTrackerTests(unittest.TestCase):
    def test_recovers_skew_through_heavy_queueing(self) -> None:
        """The reason min-filtering exists.

        Every fifth sample carries a 200 ms queueing spike on top of a
        20 ms floor. Averaging would drag the estimate into that tail;
        taking the least-queued sample per bucket does not.
        """
        tracker = ClockTracker()
        generator = random.Random(7)
        for index in range(40):
            local_send = index * 2_000.0
            true_offset = 1_000.0 + 40e-6 * local_send
            round_trip = 20.0 + (200.0 if index % 5 == 0 else generator.random() * 8.0)
            tracker.observe(_exchange(local_send, true_offset, round_trip))

        estimate = tracker.estimate()
        self.assertTrue(estimate.skew_measured)
        self.assertAlmostEqual(estimate.skew_ppm, 40.0, places=1)
        self.assertAlmostEqual(estimate.offset_at(80_000.0), 1_000.0 + 40e-6 * 80_000.0, places=1)

    def test_projected_offset_stays_within_the_reported_uncertainty(self) -> None:
        tracker = ClockTracker()
        for index in range(30):
            local_send = index * 1_000.0
            tracker.observe(_exchange(local_send, 250.0 + 30e-6 * local_send, 12.0))
        estimate = tracker.estimate()
        for local_ms in (0.0, 15_000.0, 29_000.0, 120_000.0):
            interval = estimate.to_remote(local_ms)
            self.assertTrue(interval.contains(local_ms + 250.0 + 30e-6 * local_ms), local_ms)

    def test_a_fresh_tracker_assumes_the_datasheet_bound_rather_than_zero_drift(self) -> None:
        """One sample cannot identify a slope, so no slope is claimed.

        The interval must then widen at the specified crystal tolerance --
        50 ppm is 180 ms per hour -- rather than staying narrow and wrong.
        """
        tracker = ClockTracker()
        tracker.observe(_exchange(0.0, 1_000.0, 40.0))
        estimate = tracker.estimate()

        self.assertFalse(estimate.skew_measured)
        self.assertEqual(estimate.skew_uncertainty_ppm, COMMODITY_CRYSTAL_PPM)
        # Uncertainty is measured outward from the instant the exchange
        # closed, not from an arbitrary zero.
        reference = estimate.reference_local_ms
        self.assertAlmostEqual(estimate.uncertainty_at(reference), 20.0, places=9)
        self.assertAlmostEqual(estimate.uncertainty_at(reference + 3_600_000.0), 20.0 + 180.0, places=6)
        self.assertAlmostEqual(estimate.uncertainty_at(reference - 3_600_000.0), 20.0 + 180.0, places=6)

    def test_too_short_a_span_does_not_claim_a_slope(self) -> None:
        """Samples crowded into a second have no leverage on drift."""
        tracker = ClockTracker()
        for index in range(20):
            tracker.observe(_exchange(index * 50.0, 100.0, 10.0))
        self.assertFalse(tracker.estimate().skew_measured)

    def test_samples_older_than_the_window_are_dropped(self) -> None:
        tracker = ClockTracker(window_ms=10_000.0)
        for index in range(30):
            tracker.observe(_exchange(index * 1_000.0, 0.0, 10.0))
        self.assertLessEqual(tracker.sample_count, 11)

    def test_filtering_keeps_the_least_queued_sample_per_bucket(self) -> None:
        tracker = ClockTracker(buckets=4)
        for index in range(24):
            tracker.observe(_exchange(index * 1_000.0, 0.0, 10.0 if index % 6 == 3 else 300.0))
        filtered = tracker.filtered_samples()
        self.assertLessEqual(len(filtered), 4)
        self.assertTrue(all(exchange.round_trip_ms == 10.0 for _, exchange in filtered))

    def test_resync_interval_inverts_the_drift_arithmetic(self) -> None:
        """At 50 ppm, holding a millisecond means resyncing every 20 seconds."""
        tracker = ClockTracker()
        tracker.observe(_exchange(0.0, 0.0, 0.2))
        estimate = tracker.estimate()
        self.assertAlmostEqual(estimate.resync_interval_s(1.0), (1.0 - 0.1) / (COMMODITY_CRYSTAL_PPM * 1e-6 * 1000.0), places=6)

    def test_a_tolerance_the_link_cannot_deliver_returns_zero_not_a_schedule(self) -> None:
        """No resync rate buys precision below the transfer error itself."""
        tracker = ClockTracker()
        tracker.observe(_exchange(0.0, 0.0, 40.0))
        self.assertEqual(tracker.estimate().resync_interval_s(1.0), 0.0)

    def test_estimating_before_any_exchange_is_an_error_not_a_default(self) -> None:
        with self.assertRaises(FaspError):
            ClockTracker().estimate()


if __name__ == "__main__":
    unittest.main()
