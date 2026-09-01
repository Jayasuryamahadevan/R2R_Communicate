"""A fail-safe deadline timer: when the expected thing does not happen, act.

A watchdog is the cheapest safety-relevant construct there is, and the one
most often implemented wrongly -- as a timer that logs. This one has the two
properties that make it worth having:

- **fail-safe by default.** The expiry action runs on the watchdog's own
  thread, so it still fires when the thread that should have petted it is
  wedged, deadlocked, or garbage-collecting. A watchdog that depends on the
  liveness of the thing it is watching is decorative.
- **latched.** Expiry is a state, not an event. It stays expired until
  something explicitly and locally resets it, so a flapping input cannot
  silently un-trip a safety response.

This remains a Layer 3/4 construct: it escalates by *requesting* a halt
through `fasp_harness.safety`, and the machine's actual protective stop is
still the certified Layer 1 device's job. What it buys is that a stalled
coordinator degrades toward stopped rather than toward "commands from
twenty seconds ago".
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from ..protocol.errors import FaspError
from .scheduler import NS_PER_S, Clock, SystemClock


class WatchdogExpired(FaspError):
    """Raised by `require_alive()` on a watchdog that has already tripped."""

    def __init__(self, name: str, detail: str) -> None:
        super().__init__("safety.watchdog_expired", f"Watchdog {name!r} expired: {detail}")


class DeadlineWatchdog:
    """Trip `on_expire` unless `pet()` is called at least every `timeout_s`."""

    def __init__(
        self,
        name: str,
        timeout_s: float,
        on_expire: Callable[[str], None],
        *,
        clock: Clock | None = None,
        check_interval_s: float | None = None,
        auto_reset: bool = False,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive.")
        self.name = name
        self.timeout_ns = int(timeout_s * NS_PER_S)
        self.on_expire = on_expire
        self.clock = clock or SystemClock()
        # Poll fast enough that detection latency is a small fraction of the
        # timeout itself -- a watchdog checked once per timeout can be a
        # full timeout late, doubling the real response time.
        self.check_interval_s = check_interval_s if check_interval_s is not None else max(timeout_s / 10.0, 0.001)
        self.auto_reset = auto_reset
        self._lock = threading.Lock()
        self._last_pet_ns = self.clock.monotonic_ns()
        self._expired = False
        self._expiry_count = 0
        self._worst_gap_ns = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- state -------------------------------------------------------
    @property
    def expired(self) -> bool:
        with self._lock:
            return self._expired

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "expired": self._expired,
                "expiry_count": self._expiry_count,
                "timeout_ms": self.timeout_ns / 1e6,
                "since_last_pet_ms": (self.clock.monotonic_ns() - self._last_pet_ns) / 1e6,
                "worst_gap_ms": self._worst_gap_ns / 1e6,
            }

    def pet(self) -> None:
        """Report liveness. On a latched watchdog this does NOT clear an
        existing expiry -- only `reset()` does, and only locally."""
        with self._lock:
            now_ns = self.clock.monotonic_ns()
            self._worst_gap_ns = max(self._worst_gap_ns, now_ns - self._last_pet_ns)
            self._last_pet_ns = now_ns
            if self._expired and self.auto_reset:
                self._expired = False

    def reset(self) -> None:
        """Clear a latched expiry. Local operator action only: never wire
        this to a network handler (see FASP_PROTOCOL.md ss9.1)."""
        with self._lock:
            self._expired = False
            self._last_pet_ns = self.clock.monotonic_ns()

    def require_alive(self) -> None:
        """Guard a code path that must not run behind a tripped watchdog."""
        with self._lock:
            if self._expired:
                raise WatchdogExpired(self.name, f"no liveness for more than {self.timeout_ns / 1e6:.0f}ms")

    # -- evaluation --------------------------------------------------
    def poll(self) -> bool:
        """Evaluate once; returns True if this call tripped the watchdog.

        Public and side-effecting on purpose: a deterministic test (or a
        caller already running its own cyclic executor) drives the watchdog
        by calling `poll()` on a `ManualClock` instead of starting a thread.
        """
        with self._lock:
            if self._expired:
                return False
            elapsed = self.clock.monotonic_ns() - self._last_pet_ns
            if elapsed <= self.timeout_ns:
                return False
            self._expired = True
            self._expiry_count += 1
            self._worst_gap_ns = max(self._worst_gap_ns, elapsed)
            detail = f"no liveness for {elapsed / 1e6:.0f}ms (timeout {self.timeout_ns / 1e6:.0f}ms)"
        # Called outside the lock: the expiry action escalates into the
        # safety supervisor, which must never be able to deadlock against
        # a `pet()` from another thread.
        self.on_expire(detail)
        return True

    def start(self) -> DeadlineWatchdog:
        """Run the check loop on a daemon thread."""
        if self._thread is not None:
            return self
        self._stop.clear()

        def target() -> None:
            while not self._stop.wait(self.check_interval_s):
                try:
                    self.poll()
                except Exception:  # noqa: BLE001 - a watchdog must never die
                    continue

        self._thread = threading.Thread(target=target, name=f"fasp-watchdog-{self.name}", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=max(self.check_interval_s * 4, 0.5))

    def __enter__(self) -> DeadlineWatchdog:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


class WatchdogGroup:
    """Several watchdogs, one aggregate verdict.

    A supervisory process usually watches more than one thing -- peer
    heartbeat, control-plane loop, safety-controller poll -- and the useful
    question is "is anything overdue", answered without the caller tracking
    each one.
    """

    def __init__(self) -> None:
        self._watchdogs: dict[str, DeadlineWatchdog] = {}

    def add(self, watchdog: DeadlineWatchdog) -> DeadlineWatchdog:
        self._watchdogs[watchdog.name] = watchdog
        return watchdog

    def get(self, name: str) -> DeadlineWatchdog | None:
        return self._watchdogs.get(name)

    def pet(self, name: str) -> None:
        watchdog = self._watchdogs.get(name)
        if watchdog is not None:
            watchdog.pet()

    def poll_all(self) -> list[str]:
        return [name for name, watchdog in self._watchdogs.items() if watchdog.poll()]

    @property
    def any_expired(self) -> bool:
        return any(watchdog.expired for watchdog in self._watchdogs.values())

    def status(self) -> dict[str, Any]:
        return {"any_expired": self.any_expired, "watchdogs": [watchdog.status() for watchdog in self._watchdogs.values()]}

    def start_all(self) -> None:
        for watchdog in self._watchdogs.values():
            watchdog.start()

    def stop_all(self) -> None:
        for watchdog in self._watchdogs.values():
            watchdog.stop()
