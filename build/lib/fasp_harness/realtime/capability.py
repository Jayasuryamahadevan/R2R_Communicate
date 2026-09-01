"""What real-time guarantees this host could offer, established by looking.

Every field here is read from the running system. The point is not to make
the harness faster; it is to let the safety case (`fasp_harness/safety/
case.py`) and the deployment report state timing claims that are true of
*this* machine, and to make an over-claim structurally impossible:
`hard_realtime` is not computed, it is `False`.
"""

from __future__ import annotations

import os
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# CPython's own properties, independent of kernel or hardware. These are
# why Layer 1 lives somewhere else.
INTERPRETER_LIMITS = (
    "CPython holds a global interpreter lock, so a compute-bound thread can delay every other thread in this process.",
    "CPython's cyclic garbage collector can stop all threads for an unbounded time at an unpredictable moment.",
    "Memory allocation goes through a general-purpose allocator with no bounded worst case.",
)


@dataclass(frozen=True)
class RealtimeCapability:
    """A host's measured and inspected timing posture."""

    hard_realtime: bool
    timing_class: str
    reasons: tuple[str, ...]
    os_family: str
    kernel: str
    preempt_rt: bool
    sched_fifo_available: bool
    max_rt_priority: int
    isolated_cpus: tuple[int, ...]
    cpu_count: int
    monotonic_resolution_s: float
    clock_is_monotonic_raw: bool
    containerized: bool
    cpu_quota_ratio: float | None
    measured_sleep_jitter_us: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        return f"{self.timing_class} real-time at best ({self.os_family}/{self.kernel}); hard real-time: no"


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _detect_preempt_rt() -> bool:
    if _read_text("/sys/kernel/realtime") == "1":
        return True
    version = _read_text("/proc/version") or ""
    release = platform.release()
    return "PREEMPT_RT" in version or "PREEMPT_RT" in release or "-rt" in release.lower()


def _parse_cpu_list(value: str | None) -> tuple[int, ...]:
    """Parse a Linux CPU list ("0-2,7") into concrete CPU numbers."""
    if not value:
        return ()
    cpus: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                cpus.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                cpus.append(int(part))
            except ValueError:
                continue
    return tuple(sorted(set(cpus)))


def _cpu_quota_ratio() -> float | None:
    """cgroup v2 then v1 CPU bandwidth, as a fraction of one CPU.

    A container capped below one CPU cannot hold a periodic deadline under
    load no matter what the kernel is, so this belongs in the posture.
    """
    v2 = _read_text("/sys/fs/cgroup/cpu.max")
    if v2:
        quota, _, period = v2.partition(" ")
        if quota != "max":
            try:
                return int(quota) / max(int(period or "100000"), 1)
            except ValueError:
                pass
        else:
            return None
    quota_text = _read_text("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    period_text = _read_text("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    if quota_text and period_text:
        try:
            quota_us, period_us = int(quota_text), int(period_text)
        except ValueError:
            return None
        if quota_us > 0 and period_us > 0:
            return quota_us / period_us
    return None


def _max_rt_priority() -> tuple[bool, int]:
    """Whether this process could actually enter SCHED_FIFO, and how high.

    Checked rather than assumed: an unprivileged process with
    `RLIMIT_RTPRIO` of 0 gets `EPERM` from `sched_setscheduler` even on a
    PREEMPT_RT kernel, which is the common container case.
    """
    if not hasattr(os, "sched_get_priority_max") or not hasattr(os, "SCHED_FIFO"):
        return False, 0
    try:
        ceiling = os.sched_get_priority_max(os.SCHED_FIFO)
    except (OSError, AttributeError, ValueError):
        return False, 0
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_RTPRIO)
    except (ImportError, OSError, ValueError, AttributeError):
        return False, 0
    privileged = hasattr(os, "geteuid") and os.geteuid() == 0
    if soft == 0 and not privileged:
        return False, 0
    limit = ceiling if soft < 0 or privileged else min(int(soft), ceiling)
    return limit > 0, max(limit, 0)


def measure_sleep_jitter(samples: int = 200, interval_s: float = 0.001) -> dict[str, float]:
    """Measure how late `time.sleep()` actually returns, in microseconds.

    This is the floor on any pure-Python periodic loop: a scheduler cannot
    be more punctual than its own sleep primitive.
    """
    if samples <= 0:
        return {}
    overshoot: list[float] = []
    target = time.perf_counter_ns()
    for _ in range(samples):
        target += int(interval_s * 1e9)
        remaining = (target - time.perf_counter_ns()) / 1e9
        if remaining > 0:
            time.sleep(remaining)
        overshoot.append((time.perf_counter_ns() - target) / 1000.0)
    overshoot.sort()
    return {
        "samples": float(len(overshoot)),
        "min_us": round(overshoot[0], 3),
        "p50_us": round(overshoot[len(overshoot) // 2], 3),
        "p99_us": round(overshoot[min(len(overshoot) - 1, int(len(overshoot) * 0.99))], 3),
        "max_us": round(overshoot[-1], 3),
    }


def probe_realtime_capability(*, measure: bool = True, samples: int = 200) -> RealtimeCapability:
    """Inspect (and optionally measure) this host's timing posture."""
    preempt_rt = _detect_preempt_rt()
    fifo_available, max_priority = _max_rt_priority()
    isolated = _parse_cpu_list(_read_text("/sys/devices/system/cpu/isolated"))
    quota = _cpu_quota_ratio()
    containerized = bool(os.environ.get("container") or os.environ.get("KUBERNETES_SERVICE_HOST") or Path("/.dockerenv").exists())

    reasons = list(INTERPRETER_LIMITS)
    if not preempt_rt:
        reasons.append("Kernel does not report PREEMPT_RT, so scheduling latency has no bounded worst case.")
    if not fifo_available:
        reasons.append("This process may not enter SCHED_FIFO, so it is subject to ordinary fair-share scheduling.")
    if not isolated:
        reasons.append("No isolated CPUs, so periodic work competes with every other runnable task.")
    if quota is not None and quota < 1.0:
        reasons.append(f"cgroup CPU bandwidth is capped at {quota:.2f} CPU, which can throttle a periodic loop mid-cycle.")

    # Deliberately conservative and deliberately capped: the best label
    # this function can ever return is "firm", and only when the kernel,
    # the scheduling class, and CPU isolation all cooperate.
    if preempt_rt and fifo_available and isolated:
        timing_class = "firm"
    elif fifo_available or preempt_rt:
        timing_class = "soft"
    else:
        timing_class = "best-effort"

    return RealtimeCapability(
        hard_realtime=False,
        timing_class=timing_class,
        reasons=tuple(reasons),
        os_family={"windows": "windows", "linux": "linux", "darwin": "macos"}.get(platform.system().lower(), "other"),
        kernel=platform.release() or "unknown",
        preempt_rt=preempt_rt,
        sched_fifo_available=fifo_available,
        max_rt_priority=max_priority,
        isolated_cpus=isolated,
        cpu_count=os.cpu_count() or 1,
        monotonic_resolution_s=time.get_clock_info("monotonic").resolution,
        clock_is_monotonic_raw=hasattr(time, "CLOCK_MONOTONIC_RAW"),
        containerized=containerized,
        cpu_quota_ratio=quota,
        measured_sleep_jitter_us=measure_sleep_jitter(samples) if measure else {},
    )


def request_realtime_priority(priority: int | None = None) -> tuple[bool, str]:
    """Best-effort SCHED_FIFO for the calling thread.

    Returns `(applied, detail)` and never raises: on every host where this
    is not permitted the caller must keep working at normal priority, which
    is the overwhelmingly common case (any container without
    `CAP_SYS_NICE`). Callers must treat success as an optimisation, never
    as a guarantee they have acquired.
    """
    if not hasattr(os, "sched_setscheduler") or not hasattr(os, "SCHED_FIFO"):
        return False, "SCHED_FIFO is not available on this platform."
    available, ceiling = _max_rt_priority()
    if not available:
        return False, "This process lacks the RLIMIT_RTPRIO budget to enter SCHED_FIFO."
    target = min(priority or max(ceiling // 2, 1), ceiling)
    try:
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(target))
    except (OSError, PermissionError, ValueError) as exc:
        return False, f"Kernel refused SCHED_FIFO: {exc.__class__.__name__}."
    return True, f"Running SCHED_FIFO at priority {target}; still not hard real-time (see INTERPRETER_LIMITS)."


def main() -> int:
    """`python -m fasp_harness rt-probe`."""
    import json

    capability = probe_realtime_capability()
    print(json.dumps(capability.to_dict(), indent=2, sort_keys=True, default=list))
    print(f"\n{capability.summary()}", file=sys.stderr)
    return 0
