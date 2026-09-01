"""Timing: what this process can honestly promise, measured rather than asserted.

Nothing in here is a hard real-time system, and none of it pretends to be.
CPython has a global interpreter lock and a stop-the-world garbage
collector; those two facts alone put a hard upper bound on the guarantees
any pure-Python scheduler can offer, and no amount of careful coding moves
that bound. See `probe_realtime_capability()` -- `hard_realtime` is a
constant `False` there, with the reason attached, precisely so that a
downstream report cannot accidentally claim otherwise.

What this package does provide, and what Layers 3 and 4 actually need:

- `CyclicExecutor`  a drift-free fixed-period executor with explicit
                    deadlines and an overrun policy, so a management-plane
                    loop has *defined* behaviour when it runs late rather
                    than silently sliding.
- `TimingRecorder`  bounded-memory latency histograms, so "our jitter is
                    fine" is a measurement with percentiles attached.
- `DeadlineWatchdog` a fail-safe timer: if the thing that should have
                    happened did not happen in time, something safe happens
                    instead, automatically.
- `probe_realtime_capability()` an honest description of what the host
                    kernel would permit, used by the safety case and the
                    security posture check.
"""

from __future__ import annotations

from .capability import RealtimeCapability, probe_realtime_capability
from .scheduler import Clock, CyclicExecutor, ManualClock, OverrunPolicy, SystemClock, TimingRecorder, TimingReport
from .watchdog import DeadlineWatchdog, WatchdogExpired

__all__ = [
    "Clock",
    "CyclicExecutor",
    "DeadlineWatchdog",
    "ManualClock",
    "OverrunPolicy",
    "RealtimeCapability",
    "SystemClock",
    "TimingRecorder",
    "TimingReport",
    "WatchdogExpired",
    "probe_realtime_capability",
]
