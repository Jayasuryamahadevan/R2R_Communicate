"""A drift-free periodic executor with explicit deadlines and measured jitter.

The value of this module is not speed. It is *definedness*. An ordinary
`while True: work(); time.sleep(period)` loop has three properties that make
it unusable as evidence for anything:

- it drifts, because the sleep starts after the work rather than at a fixed
  release time, so the period is really `period + work_duration`;
- it has no deadline, so "we were late" is not an event that exists;
- it has no defined behaviour when a cycle overruns -- it just silently
  slides, and every later cycle inherits the lateness.

`CyclicExecutor` fixes all three: releases are computed from an absolute
origin (`release_n = origin + n * period`), every cycle has a deadline it
either meets or misses, and an overrun is a first-class event routed
through an explicit `OverrunPolicy`. Latency is recorded into bounded
histograms so a claim about jitter comes with percentiles.

`Clock` exists so the scheduler's own logic is testable *deterministically*:
`ManualClock` advances only when told to, so a test can prove the release
schedule never drifts and that each overrun policy does exactly what it
says, without depending on the host being quiet.

This is Layer 3/4 machinery. It is emphatically not a Layer 1 control loop:
see `fasp_harness.realtime.capability` for why nothing running in CPython
can be one.
"""

from __future__ import annotations

import threading
import time
from bisect import bisect_left
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

NS_PER_S = 1_000_000_000


class Clock(Protocol):
    """The two operations a scheduler needs, and nothing else."""

    def monotonic_ns(self) -> int: ...

    def sleep_until_ns(self, deadline_ns: int) -> None: ...


class SystemClock:
    """The real clock. `perf_counter_ns` because it is the highest-resolution
    monotonic source CPython exposes and is never adjusted by NTP."""

    __slots__ = ()

    def monotonic_ns(self) -> int:
        return time.perf_counter_ns()

    def sleep_until_ns(self, deadline_ns: int) -> None:
        remaining = deadline_ns - self.monotonic_ns()
        if remaining > 0:
            time.sleep(remaining / NS_PER_S)


class ManualClock:
    """A virtual clock for deterministic tests.

    `sleep_until_ns` jumps straight to the deadline (never backwards), so a
    scheduler under test runs its whole schedule instantly and in a fully
    reproducible order. `advance()` lets a test inject a stall of an exact
    size to provoke a specific overrun.
    """

    def __init__(self, start_ns: int = 0) -> None:
        self._now = start_ns
        self.sleeps: list[int] = []

    def monotonic_ns(self) -> int:
        return self._now

    def advance(self, delta_ns: int) -> None:
        if delta_ns < 0:
            raise ValueError("A monotonic clock cannot move backwards.")
        self._now += delta_ns

    def sleep_until_ns(self, deadline_ns: int) -> None:
        self.sleeps.append(max(0, deadline_ns - self._now))
        self._now = max(self._now, deadline_ns)


class OverrunPolicy(Enum):
    """What a cycle that misses its deadline does to the *schedule*.

    The right answer is domain-specific, which is exactly why it is a
    parameter rather than a hardcoded behaviour.
    """

    SKIP = "skip"
    """Drop the missed releases and resynchronise to the next future one.
    Correct for sampling/telemetry: a stale cycle has no value."""

    CATCH_UP = "catch_up"
    """Run the missed cycles back to back. Correct for accounting work
    where every tick must eventually happen (lease sweeps, retries)."""

    FAIL_SAFE = "fail_safe"
    """Stop the loop and invoke `on_overrun`. Correct when being late is
    itself the hazard -- this is the policy a supervisory loop uses to
    escalate into a halt request."""


# Log-spaced histogram edges in microseconds: dense where scheduling jitter
# actually lives (1us-10ms) and still bounded out to 10s, in 34 buckets, so
# a long-running loop's memory does not grow with its uptime.
_BUCKET_EDGES_US: tuple[float, ...] = tuple(
    value for exponent in range(0, 8) for value in (1 * 10**exponent, 2 * 10**exponent, 5 * 10**exponent)
) + (1e8,)


@dataclass
class TimingRecorder:
    """Bounded-memory latency statistics: exact extremes, bucketed quantiles.

    Percentiles are interpolated from the histogram, so they are accurate
    to a bucket rather than exact -- which is the correct trade for a
    recorder that must run forever inside a periodic loop without
    allocating per sample.
    """

    name: str
    count: int = 0
    total_us: float = 0.0
    min_us: float = float("inf")
    max_us: float = float("-inf")
    buckets: list[int] = field(default_factory=lambda: [0] * (len(_BUCKET_EDGES_US) + 1))

    def record_ns(self, value_ns: int) -> None:
        self.record_us(value_ns / 1000.0)

    def record_us(self, value_us: float) -> None:
        self.count += 1
        self.total_us += value_us
        if value_us < self.min_us:
            self.min_us = value_us
        if value_us > self.max_us:
            self.max_us = value_us
        self.buckets[bisect_left(_BUCKET_EDGES_US, abs(value_us))] += 1

    def quantile_us(self, fraction: float) -> float:
        if self.count == 0:
            return 0.0
        target = max(1, min(self.count, int(round(fraction * self.count))))
        seen = 0
        for index, occupancy in enumerate(self.buckets):
            seen += occupancy
            if seen >= target:
                if index >= len(_BUCKET_EDGES_US):
                    return self.max_us
                return min(_BUCKET_EDGES_US[index], self.max_us)
        return self.max_us

    def to_dict(self) -> dict[str, Any]:
        if self.count == 0:
            return {"name": self.name, "count": 0}
        return {
            "name": self.name,
            "count": self.count,
            "min_us": round(self.min_us, 3),
            "mean_us": round(self.total_us / self.count, 3),
            "p50_us": round(self.quantile_us(0.50), 3),
            "p95_us": round(self.quantile_us(0.95), 3),
            "p99_us": round(self.quantile_us(0.99), 3),
            "max_us": round(self.max_us, 3),
        }


@dataclass
class TimingReport:
    """One executor run's evidence: schedule shape, jitter, and misses."""

    name: str
    period_ns: int
    deadline_ns: int
    cycles: int
    overruns: int
    skipped_cycles: int
    release_jitter: TimingRecorder
    execution: TimingRecorder
    response: TimingRecorder

    @property
    def deadline_miss_ratio(self) -> float:
        return self.overruns / self.cycles if self.cycles else 0.0

    def meets(self, *, max_miss_ratio: float = 0.0, max_response_us: float | None = None) -> tuple[bool, str]:
        """Check this run against a stated budget. Used as safety-case and
        HIL evidence, so it returns the reason it failed, not just a bool."""
        if self.cycles == 0:
            return False, "No cycles ran, so nothing was demonstrated."
        if self.deadline_miss_ratio > max_miss_ratio:
            return False, f"Deadline miss ratio {self.deadline_miss_ratio:.4f} exceeds budget {max_miss_ratio:.4f} ({self.overruns}/{self.cycles} cycles late)."
        if max_response_us is not None and self.response.max_us > max_response_us:
            return False, f"Worst-case response {self.response.max_us:.1f}us exceeds budget {max_response_us:.1f}us."
        return True, f"{self.cycles} cycles, {self.overruns} late, worst-case response {self.response.max_us:.1f}us."

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "period_us": self.period_ns / 1000.0,
            "deadline_us": self.deadline_ns / 1000.0,
            "cycles": self.cycles,
            "overruns": self.overruns,
            "skipped_cycles": self.skipped_cycles,
            "deadline_miss_ratio": round(self.deadline_miss_ratio, 6),
            "release_jitter": self.release_jitter.to_dict(),
            "execution": self.execution.to_dict(),
            "response": self.response.to_dict(),
        }


class CyclicExecutor:
    """Runs `work()` once per period against an absolute release schedule."""

    def __init__(
        self,
        period_s: float,
        work: Callable[[int], Any],
        *,
        name: str = "cyclic",
        deadline_s: float | None = None,
        clock: Clock | None = None,
        overrun_policy: OverrunPolicy = OverrunPolicy.SKIP,
        on_overrun: Callable[[int, int], None] | None = None,
    ) -> None:
        if period_s <= 0:
            raise ValueError("period_s must be positive.")
        deadline_s = period_s if deadline_s is None else deadline_s
        if not 0 < deadline_s <= period_s:
            raise ValueError("deadline_s must be positive and no larger than period_s.")
        self.name = name
        self.period_ns = int(period_s * NS_PER_S)
        self.deadline_ns = int(deadline_s * NS_PER_S)
        self.work = work
        self.clock = clock or SystemClock()
        self.overrun_policy = overrun_policy
        self.on_overrun = on_overrun
        self._stop = threading.Event()
        self._release_jitter = TimingRecorder(f"{name}.release_jitter")
        self._execution = TimingRecorder(f"{name}.execution")
        self._response = TimingRecorder(f"{name}.response")
        self._cycles = 0
        self._overruns = 0
        self._skipped = 0

    def stop(self) -> None:
        """Ask the loop to finish after the current cycle. Thread-safe."""
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def run(self, *, cycles: int | None = None) -> TimingReport:
        """Run until `cycles` have completed, `stop()` is called, or a
        FAIL_SAFE overrun trips. Returns the run's timing evidence."""
        origin = self.clock.monotonic_ns()
        index = 0
        while not self._stop.is_set() and (cycles is None or self._cycles < cycles):
            release = origin + index * self.period_ns
            self.clock.sleep_until_ns(release)
            woke = self.clock.monotonic_ns()
            self._release_jitter.record_ns(woke - release)

            started = woke
            try:
                self.work(index)
            finally:
                finished = self.clock.monotonic_ns()
                self._execution.record_ns(finished - started)
                self._response.record_ns(finished - release)
                self._cycles += 1

            index += 1
            if finished - release <= self.deadline_ns:
                continue

            self._overruns += 1
            if self.on_overrun is not None:
                self.on_overrun(index - 1, finished - release)
            if self.overrun_policy is OverrunPolicy.FAIL_SAFE:
                self._stop.set()
            elif self.overrun_policy is OverrunPolicy.SKIP:
                # Resynchronise to the next release strictly in the future,
                # so lateness is absorbed once instead of inherited by
                # every subsequent cycle.
                missed = (finished - origin) // self.period_ns + 1 - index
                if missed > 0:
                    self._skipped += missed
                    index += missed
        return self.report()

    def report(self) -> TimingReport:
        return TimingReport(
            name=self.name,
            period_ns=self.period_ns,
            deadline_ns=self.deadline_ns,
            cycles=self._cycles,
            overruns=self._overruns,
            skipped_cycles=self._skipped,
            release_jitter=self._release_jitter,
            execution=self._execution,
            response=self._response,
        )

    def run_in_thread(self, *, cycles: int | None = None, realtime_priority: int | None = None) -> threading.Thread:
        """Run the loop on its own daemon thread, optionally asking the
        kernel for SCHED_FIFO first (best effort; see
        `capability.request_realtime_priority`)."""

        def target() -> None:
            if realtime_priority is not None:
                from .capability import request_realtime_priority

                request_realtime_priority(realtime_priority)
            self.run(cycles=cycles)

        thread = threading.Thread(target=target, name=f"fasp-{self.name}", daemon=True)
        thread.start()
        return thread


def run_schedule(period_s: float, work: Callable[[int], Any], cycles: int, *, clock: Clock | None = None, **kwargs: Any) -> TimingReport:
    """Convenience: run a bounded schedule and return its evidence."""
    return CyclicExecutor(period_s, work, clock=clock, **kwargs).run(cycles=cycles)


def merge_reports(reports: Iterable[TimingReport]) -> dict[str, Any]:
    """Summarise several loops' evidence into one report body."""
    collected = list(reports)
    return {
        "loops": [report.to_dict() for report in collected],
        "worst_case_response_us": round(max((report.response.max_us for report in collected if report.cycles), default=0.0), 3),
        "total_overruns": sum(report.overruns for report in collected),
        "total_cycles": sum(report.cycles for report in collected),
    }
