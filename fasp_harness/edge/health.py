"""Liveness, readiness, startup, and drain -- four different questions.

Orchestrators (systemd, Kubernetes, a plant's own supervisor) make very
different decisions from these, and collapsing them into one `/health`
endpoint causes both classic failures: restarting a process that was merely
busy, and routing work to a process that was merely running.

    startup   "has initialisation finished?"  -> keep waiting, don't kill
    liveness  "is this process wedged?"       -> restart it
    readiness "should it receive work now?"   -> route or don't route
    drain     "is it finishing up to stop?"   -> stop routing, don't kill

A hot-standby node is the case that makes the distinction concrete: it is
alive, it is not wedged, it must not be restarted -- and it must not be
given work, because it does not hold the leader lease. That is
`ready=False, live=True`, which a single boolean cannot express.

Checks are registered as callables and evaluated on demand, with per-check
error containment: a check that raises reports as failed with its exception
type, and never takes the probe endpoint down with it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class HealthState(StrEnum):
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DRAINING = "draining"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "duration_ms": round(self.duration_ms, 3)}


@dataclass
class _Check:
    name: str
    run: Callable[[], tuple[bool, str]]
    critical: bool
    affects_readiness: bool


class HealthRegistry:
    """The four probes, plus the checks that answer them."""

    def __init__(self, *, node_id: str = "local") -> None:
        self.node_id = node_id
        self._lock = threading.Lock()
        self._checks: list[_Check] = []
        self._started_at = time.monotonic()
        self._startup_complete = False
        self._draining = False

    # -- registration ---------------------------------------------------
    def register(self, name: str, run: Callable[[], tuple[bool, str]], *, critical: bool = False, affects_readiness: bool = True) -> None:
        """`critical` checks fail liveness (restart me). Everything else can
        only fail readiness (don't route to me) -- the default, because a
        dependency being down is almost never a reason to restart."""
        with self._lock:
            self._checks = [check for check in self._checks if check.name != name]
            self._checks.append(_Check(name, run, critical, affects_readiness))

    def mark_started(self) -> None:
        with self._lock:
            self._startup_complete = True

    def begin_drain(self) -> None:
        """Stop accepting new work; stay alive to finish what is in flight."""
        with self._lock:
            self._draining = True

    @property
    def draining(self) -> bool:
        with self._lock:
            return self._draining

    # -- evaluation ------------------------------------------------------
    def evaluate(self) -> list[CheckResult]:
        with self._lock:
            checks = list(self._checks)
        results: list[CheckResult] = []
        for check in checks:
            started = time.perf_counter()
            try:
                ok, detail = check.run()
            except Exception as exc:  # noqa: BLE001 - a probe must never crash
                ok, detail = False, f"check raised {exc.__class__.__name__}"
            results.append(CheckResult(check.name, bool(ok), str(detail)[:200], (time.perf_counter() - started) * 1000.0))
        return results

    def _by_name(self) -> dict[str, _Check]:
        with self._lock:
            return {check.name: check for check in self._checks}

    def live(self) -> tuple[bool, dict[str, Any]]:
        results = self.evaluate()
        registry = self._by_name()
        failed = [result for result in results if not result.ok and registry[result.name].critical]
        return not failed, self._body(results, HealthState.UNHEALTHY if failed else HealthState.HEALTHY)

    def ready(self) -> tuple[bool, dict[str, Any]]:
        with self._lock:
            starting, draining = not self._startup_complete, self._draining
        results = self.evaluate()
        registry = self._by_name()
        blocking = [result for result in results if not result.ok and registry[result.name].affects_readiness]
        if starting:
            return False, self._body(results, HealthState.STARTING)
        if draining:
            return False, self._body(results, HealthState.DRAINING)
        if blocking:
            return False, self._body(results, HealthState.DEGRADED)
        return True, self._body(results, HealthState.HEALTHY)

    def started(self) -> tuple[bool, dict[str, Any]]:
        with self._lock:
            complete = self._startup_complete
        return complete, self._body([], HealthState.HEALTHY if complete else HealthState.STARTING)

    def snapshot(self) -> dict[str, Any]:
        """Everything at once, for an operator rather than an orchestrator."""
        live, _ = self.live()
        ready, body = self.ready()
        return {**body, "live": live, "ready": ready}

    def _body(self, results: list[CheckResult], state: HealthState) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "state": state.value,
            "uptime_s": round(time.monotonic() - self._started_at, 3),
            "checks": [result.to_dict() for result in results],
        }
