"""Timing: deterministic scheduling, measured jitter, fail-safe watchdogs.

Every scheduler test runs on a `ManualClock`, so it asserts about the
scheduler's logic rather than about how quiet the CI machine happened to be.
"""

from __future__ import annotations

import unittest

from fasp_harness.realtime.capability import INTERPRETER_LIMITS, probe_realtime_capability
from fasp_harness.realtime.scheduler import (
    CyclicExecutor,
    ManualClock,
    OverrunPolicy,
    TimingRecorder,
    merge_reports,
)
from fasp_harness.realtime.watchdog import DeadlineWatchdog, WatchdogExpired, WatchdogGroup


class CyclicExecutorTests(unittest.TestCase):
    def test_releases_are_on_an_absolute_grid_and_never_drift(self) -> None:
        """The failure this exists to prevent: `work(); sleep(period)`, whose
        real period is `period + work_duration` and drifts without bound."""
        clock = ManualClock()
        releases: list[int] = []

        def work(index: int) -> None:
            releases.append(clock.monotonic_ns())
            clock.advance(3_000_000)  # 3ms of work inside a 10ms period

        CyclicExecutor(0.01, work, clock=clock, name="grid").run(cycles=200)
        self.assertEqual(releases, [index * 10_000_000 for index in range(200)])

    def test_deadline_misses_are_counted_not_absorbed(self) -> None:
        clock = ManualClock()
        overruns: list[int] = []
        executor = CyclicExecutor(
            0.01,
            lambda index: clock.advance(15_000_000),
            clock=clock,
            deadline_s=0.008,
            overrun_policy=OverrunPolicy.SKIP,
            on_overrun=lambda index, late: overruns.append(late),
        )
        report = executor.run(cycles=5)
        self.assertEqual(report.cycles, 5)
        self.assertEqual(report.overruns, 5)
        self.assertEqual(len(overruns), 5)
        self.assertGreater(report.deadline_miss_ratio, 0.99)

    def test_skip_policy_resynchronises_instead_of_inheriting_lateness(self) -> None:
        clock = ManualClock()
        executor = CyclicExecutor(0.01, lambda index: clock.advance(35_000_000), clock=clock, overrun_policy=OverrunPolicy.SKIP)
        report = executor.run(cycles=4)
        self.assertGreater(report.skipped_cycles, 0)

    def test_catch_up_policy_runs_every_missed_cycle(self) -> None:
        clock = ManualClock()
        executor = CyclicExecutor(0.01, lambda index: clock.advance(35_000_000), clock=clock, overrun_policy=OverrunPolicy.CATCH_UP)
        report = executor.run(cycles=4)
        self.assertEqual(report.skipped_cycles, 0)
        self.assertEqual(report.cycles, 4)

    def test_fail_safe_policy_stops_the_loop_and_escalates(self) -> None:
        clock = ManualClock()
        escalations: list[int] = []
        executor = CyclicExecutor(
            0.01,
            lambda index: clock.advance(50_000_000),
            clock=clock,
            overrun_policy=OverrunPolicy.FAIL_SAFE,
            on_overrun=lambda index, late: escalations.append(late),
        )
        report = executor.run(cycles=100)
        self.assertEqual(report.cycles, 1, "FAIL_SAFE must stop at the first overrun, not keep running late.")
        self.assertEqual(len(escalations), 1)
        self.assertTrue(executor.stopped)

    def test_report_meets_a_stated_budget_or_says_why_not(self) -> None:
        clock = ManualClock()
        report = CyclicExecutor(0.01, lambda index: None, clock=clock).run(cycles=50)
        ok, detail = report.meets(max_miss_ratio=0.0)
        self.assertTrue(ok, detail)

        clock = ManualClock()
        late = CyclicExecutor(0.01, lambda index: clock.advance(20_000_000), clock=clock).run(cycles=5)
        ok, detail = late.meets(max_miss_ratio=0.0)
        self.assertFalse(ok)
        self.assertIn("miss ratio", detail)

    def test_merge_reports_summarises_several_loops(self) -> None:
        clock = ManualClock()
        first = CyclicExecutor(0.01, lambda index: None, clock=clock, name="a").run(cycles=10)
        second = CyclicExecutor(0.02, lambda index: None, clock=ManualClock(), name="b").run(cycles=5)
        merged = merge_reports([first, second])
        self.assertEqual(merged["total_cycles"], 15)
        self.assertEqual(merged["total_overruns"], 0)


class TimingRecorderTests(unittest.TestCase):
    def test_quantiles_are_bounded_by_the_observed_extremes(self) -> None:
        recorder = TimingRecorder("t")
        for value in range(1, 1001):
            recorder.record_us(float(value))
        self.assertEqual(recorder.count, 1000)
        self.assertEqual(recorder.min_us, 1.0)
        self.assertEqual(recorder.max_us, 1000.0)
        self.assertLessEqual(recorder.quantile_us(0.5), recorder.max_us)
        self.assertLessEqual(recorder.quantile_us(0.99), recorder.max_us)
        self.assertGreaterEqual(recorder.quantile_us(0.99), recorder.quantile_us(0.5))

    def test_memory_is_bounded_regardless_of_sample_count(self) -> None:
        """A recorder inside a loop that runs for months must not grow."""
        recorder = TimingRecorder("t")
        buckets = len(recorder.buckets)
        for value in range(50_000):
            recorder.record_us(float(value % 997))
        self.assertEqual(len(recorder.buckets), buckets)


class WatchdogTests(unittest.TestCase):
    def test_trips_only_after_the_timeout_and_then_latches(self) -> None:
        clock = ManualClock()
        expiries: list[str] = []
        watchdog = DeadlineWatchdog("loop", 1.0, expiries.append, clock=clock)

        clock.advance(900_000_000)
        self.assertFalse(watchdog.poll())
        self.assertFalse(watchdog.expired)

        clock.advance(200_000_000)
        self.assertTrue(watchdog.poll())
        self.assertTrue(watchdog.expired)
        self.assertEqual(len(expiries), 1)

        # Latched: a second poll does not re-fire, and petting does not clear.
        self.assertFalse(watchdog.poll())
        watchdog.pet()
        self.assertTrue(watchdog.expired)
        self.assertEqual(len(expiries), 1)

    def test_require_alive_guards_a_code_path_behind_a_tripped_watchdog(self) -> None:
        clock = ManualClock()
        watchdog = DeadlineWatchdog("loop", 1.0, lambda detail: None, clock=clock)
        watchdog.require_alive()
        clock.advance(2_000_000_000)
        watchdog.poll()
        with self.assertRaises(WatchdogExpired):
            watchdog.require_alive()

    def test_local_reset_clears_a_latched_watchdog(self) -> None:
        clock = ManualClock()
        watchdog = DeadlineWatchdog("loop", 1.0, lambda detail: None, clock=clock)
        clock.advance(2_000_000_000)
        watchdog.poll()
        watchdog.reset()
        self.assertFalse(watchdog.expired)

    def test_auto_reset_watchdogs_recover_on_the_next_pet(self) -> None:
        clock = ManualClock()
        watchdog = DeadlineWatchdog("advisory", 1.0, lambda detail: None, clock=clock, auto_reset=True)
        clock.advance(2_000_000_000)
        watchdog.poll()
        self.assertTrue(watchdog.expired)
        watchdog.pet()
        self.assertFalse(watchdog.expired)

    def test_worst_gap_is_recorded_for_evidence(self) -> None:
        clock = ManualClock()
        watchdog = DeadlineWatchdog("loop", 10.0, lambda detail: None, clock=clock)
        clock.advance(3_000_000_000)
        watchdog.pet()
        self.assertAlmostEqual(watchdog.status()["worst_gap_ms"], 3000.0, places=3)

    def test_group_reports_an_aggregate_verdict(self) -> None:
        clock = ManualClock()
        group = WatchdogGroup()
        group.add(DeadlineWatchdog("a", 1.0, lambda detail: None, clock=clock))
        group.add(DeadlineWatchdog("b", 5.0, lambda detail: None, clock=clock))
        clock.advance(2_000_000_000)
        self.assertEqual(group.poll_all(), ["a"])
        self.assertTrue(group.any_expired)
        self.assertEqual(len(group.status()["watchdogs"]), 2)


class RealtimeCapabilityTests(unittest.TestCase):
    def test_hard_realtime_is_never_claimed_and_the_reasons_are_recorded(self) -> None:
        """Not computed -- constant. A refactor that made this conditional
        would be the bug this test exists to catch."""
        capability = probe_realtime_capability(measure=False)
        self.assertFalse(capability.hard_realtime)
        self.assertIn(capability.timing_class, {"best-effort", "soft", "firm"})
        for limit in INTERPRETER_LIMITS:
            self.assertIn(limit, capability.reasons)
        self.assertIn("hard real-time: no", capability.summary())

    def test_probe_serialises_for_a_report(self) -> None:
        payload = probe_realtime_capability(measure=False).to_dict()
        self.assertFalse(payload["hard_realtime"])
        self.assertGreaterEqual(payload["cpu_count"], 1)
        self.assertGreater(payload["monotonic_resolution_s"], 0.0)

    def test_measurement_produces_percentiles(self) -> None:
        measured = probe_realtime_capability(measure=True, samples=20).measured_sleep_jitter_us
        self.assertEqual(measured["samples"], 20.0)
        self.assertLessEqual(measured["p50_us"], measured["max_us"])


if __name__ == "__main__":
    unittest.main()
