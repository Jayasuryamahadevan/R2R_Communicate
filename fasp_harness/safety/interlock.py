"""The supervisory safety object: latch, escalate, and refuse to clear.

`SafetySupervisor` is what a Layer 3 coordinator is allowed to have. It:

- polls a `SafetyControllerDriver` on a cyclic schedule and treats silence
  as unsafe (`stale_after_s`);
- accepts a halt *demand* from any source -- a peer's `safety.halt`, a
  watchdog expiry, a twin divergence, a lost leader lease, an operator --
  and latches it;
- forwards the demand to the safety controller, which may or may not have a
  request input, and never depends on it having one;
- publishes a permission (`permit_motion`) that mission dispatch consults
  *before* work is handed to a vehicle;
- refuses, structurally, to clear itself from anything that came in over a
  network. `clear()` takes an `origin` and rejects every value but
  `LOCAL_OPERATOR`, and the underlying controller must independently report
  that its own demands are gone and its manual reset has been done.

The last point is the one that matters. Every other property here is
convenience; that one is the layer boundary.

Registered `SafetyFunction` records are declarations *about* Layer 1, not
implementations of it: they say "this machine has an E-stop assessed to
PL d Cat 3, implemented by that certified controller, and here is the
evidence". The safety case reads them, and marks any function whose
`implemented_by` is this software as an immediate, hard failure.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from ..layers import Layer, LayerViolation
from ..protocol.errors import FaspError
from ..timestamps import now, stamp
from .drivers import SafetyControllerDriver, SafetyStatus

LOCAL_OPERATOR = "local-operator"

# Demand sources that may never clear a latch, enumerated so that adding a
# new escalation path cannot accidentally add a new clearing path.
NETWORK_ORIGINS = frozenset({"peer", "network", "fleet", "cloud", "wms", "mes", "erp", "twin", "watchdog", "supervisor"})


@dataclass(frozen=True)
class SafetyFunction:
    """A declaration about a Layer 1 safety function that exists elsewhere."""

    id: str
    description: str
    integrity_level: str
    standard: str
    implemented_by: str
    response_time_ms: float | None = None
    demand_sources: tuple[str, ...] = ()
    verified_by: tuple[str, ...] = ()
    layer: Layer = Layer.L1_SAFETY

    def __post_init__(self) -> None:
        if self.layer is not Layer.L1_SAFETY:
            raise LayerViolation(f"Safety function {self.id!r} must be declared at Layer 1.")

    @property
    def implemented_in_software_here(self) -> bool:
        """Whether this declaration claims *this process* is the safety
        function -- which would be false in every real deployment and is
        treated as a safety-case failure wherever it appears."""
        return self.implemented_by.strip().lower() in {"fasp", "fasp-harness", "this software", "software", "python"}

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "layer": int(self.layer)}


@dataclass(frozen=True)
class SafetyDemand:
    """One recorded reason the system was asked to stop."""

    sequence: int
    source: str
    origin: str
    reason: str
    at: str
    status_at_demand: dict[str, Any] = field(default_factory=dict)
    forwarded_to_controller: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SafetySupervisor:
    """Observes Layer 1, latches halts, and gates Layer 3 dispatch."""

    def __init__(
        self,
        driver: SafetyControllerDriver | None = None,
        *,
        stale_after_s: float = 2.0,
        max_speed_mps: float = 1.5,
        on_demand: Callable[[SafetyDemand], None] | None = None,
        require_controller: bool = True,
    ) -> None:
        self.driver = driver
        self.stale_after_s = stale_after_s
        self.max_speed_mps = max_speed_mps
        self.on_demand = on_demand
        # A deployment with actuation but no observable safety controller is
        # a deployment whose Layer 1 state this process cannot see. Default
        # to refusing to permit motion in that case rather than assuming.
        self.require_controller = require_controller
        self._lock = threading.RLock()
        self._latched = False
        self._sequence = 0
        self._demands: list[SafetyDemand] = []
        self._functions: dict[str, SafetyFunction] = {}
        self._last_status: SafetyStatus | None = None
        self._last_sample_monotonic: float | None = None
        self._poll_failures = 0

    # -- declarations -------------------------------------------------
    def register_function(self, function: SafetyFunction) -> SafetyFunction:
        with self._lock:
            self._functions[function.id] = function
        return function

    @property
    def functions(self) -> list[SafetyFunction]:
        with self._lock:
            return sorted(self._functions.values(), key=lambda item: item.id)

    # -- observation ---------------------------------------------------
    def poll(self) -> SafetyStatus:
        """Sample the controller once. Never raises: an exception on the
        safety path would be indistinguishable from a missed sample, so a
        failure becomes an explicitly unreachable status instead."""
        if self.driver is None:
            status = SafetyStatus.unreachable("none", "No safety controller driver is configured.")
        else:
            try:
                status = self.driver.read_status()
            except Exception as exc:  # noqa: BLE001 - see docstring
                self._poll_failures += 1
                status = SafetyStatus.unreachable(getattr(self.driver, "device", "unknown"), f"Driver raised {exc.__class__.__name__}.")
        with self._lock:
            self._last_status = status
            self._last_sample_monotonic = time.monotonic()
            # A controller reporting its own demand latches the supervisor
            # too, so a dispatch decision made a moment later cannot race
            # ahead of the observation that should have stopped it.
            if status.reachable and not status.safe_to_move and not self._latched:
                self._latch_locked("safety-controller", "controller", status.detail or "Safety controller reports a demand.", status)
        return status

    def current_status(self) -> SafetyStatus:
        """The most recent sample, aged and marked stale if too old."""
        with self._lock:
            status, sampled = self._last_status, self._last_sample_monotonic
        if status is None or sampled is None:
            return SafetyStatus.unreachable(getattr(self.driver, "device", "none"), "The safety controller has never been sampled.")
        age_ms = (time.monotonic() - sampled) * 1000.0
        stale = age_ms > self.stale_after_s * 1000.0
        detail = status.detail or ("Sample is older than the configured staleness budget." if stale else "")
        return SafetyStatus(**{**asdict(status), "age_ms": round(age_ms, 3), "stale": stale or status.stale, "detail": detail})

    # -- demands --------------------------------------------------------
    def demand_halt(self, source: str, reason: str, *, origin: str = "peer") -> SafetyDemand:
        """Latch a halt. Always safe to honour, from anyone, immediately."""
        status = self.current_status()
        with self._lock:
            demand = self._latch_locked(source, origin, reason, status)
        if self.on_demand is not None:
            self.on_demand(demand)
        return demand

    def _latch_locked(self, source: str, origin: str, reason: str, status: SafetyStatus) -> SafetyDemand:
        self._latched = True
        self._sequence += 1
        forwarded = False
        if self.driver is not None:
            try:
                forwarded = bool(self.driver.request_stop(reason))
            except Exception:  # noqa: BLE001 - a driver fault must not stop the latch
                forwarded = False
        demand = SafetyDemand(
            sequence=self._sequence,
            source=str(source)[:120],
            origin=str(origin)[:60],
            reason=str(reason)[:200],
            at=stamp(now()),
            status_at_demand=status.to_dict(),
            forwarded_to_controller=forwarded,
        )
        # Bounded history: a supervisor runs for months, and the useful
        # window is the recent one plus the count.
        self._demands.append(demand)
        del self._demands[:-256]
        return demand

    @property
    def latched(self) -> bool:
        with self._lock:
            return self._latched

    def clear(self, *, origin: str, operator: str, note: str = "") -> dict[str, Any]:
        """Clear the latch. Local operator only, and only when Layer 1 agrees.

        Three independent conditions, all required:
          1. the caller is local (not any network origin);
          2. the safety controller is reachable and reports every channel
             clear -- including that its own manual reset has been done;
          3. no demand has arrived since (re-checked under the lock).
        """
        if origin != LOCAL_OPERATOR or origin in NETWORK_ORIGINS:
            raise LayerViolation("A safety halt can only be cleared by a local operator at the machine, never over the network.")
        status = self.poll()
        if self.driver is not None and not status.reachable:
            raise FaspError("safety.precondition_failed", "Cannot clear a halt while the safety controller is unreachable.")
        if self.driver is not None and not status.safe_to_move:
            raise FaspError("safety.precondition_failed", "The safety controller still reports a demand; perform the local reset at the machine first.")
        with self._lock:
            self._latched = False
            cleared = {
                "type": "safety.cleared",
                "cleared_by": str(operator)[:120],
                "note": str(note)[:200],
                "at": stamp(now()),
                "demands_before_clear": self._sequence,
            }
        return cleared

    # -- permission -------------------------------------------------------
    def permit_motion(self, *, requested_speed_mps: float = 0.0, reservation_active: bool = True) -> None:
        """Raise unless supervisory preconditions for motion currently hold.

        This is a *supervisory* gate, deliberately upstream of the machine's
        own protective stop rather than a replacement for it: passing here
        means Layer 3 has no reason to withhold work, not that it is
        physically safe to move. Only Layer 1 can say that, and it says it
        by not stopping.
        """
        status = self.current_status()
        with self._lock:
            latched = self._latched
        if latched:
            raise FaspError("safety.estop_active", "A safety halt is latched; a local reset is required before work resumes.")
        if self.driver is None:
            if self.require_controller:
                raise FaspError("safety.precondition_failed", "No safety controller is observable, so motion cannot be permitted.")
        elif not status.reachable:
            # `detail` distinguishes the two very different cases that both
            # arrive here: a controller that answered and said something
            # bad, and one that has never been sampled at all.
            raise FaspError("safety.precondition_failed", status.detail or "The safety controller is unreachable; treating its state as unsafe.")
        elif status.stale:
            raise FaspError("safety.precondition_failed", f"The safety controller sample is {status.age_ms:.0f}ms old, beyond the {self.stale_after_s * 1000:.0f}ms budget.")
        elif not status.safe_to_move:
            raise FaspError("safety.estop_active", "The safety controller reports an active demand.")
        if not reservation_active:
            raise FaspError("safety.precondition_failed", "No active space-time reservation for the requested motion.")
        if not 0 <= requested_speed_mps <= self.max_speed_mps:
            raise FaspError("safety.speed_limit", f"Requested speed exceeds the supervisory envelope of {self.max_speed_mps} m/s.")

    def permitted(self, **kwargs: Any) -> tuple[bool, str]:
        """Non-raising form, for reports and preflight checks."""
        try:
            self.permit_motion(**kwargs)
        except FaspError as error:
            return False, error.detail
        return True, "Supervisory preconditions hold."

    # -- reporting ----------------------------------------------------------
    def status(self) -> dict[str, Any]:
        """The `safety.status` response body."""
        status = self.current_status()
        with self._lock:
            latched, demands, sequence = self._latched, list(self._demands[-5:]), self._sequence
        return {
            "halt_requested": latched,
            "halt_reason": demands[-1].reason if demands else None,
            "safe_to_move": (not latched) and status.safe_to_move,
            "controller": status.to_dict(),
            "demand_count": sequence,
            "recent_demands": [demand.to_dict() for demand in demands],
            "clearing_policy": "local operator at the machine only; never over the network",
        }

    def evidence(self) -> dict[str, Any]:
        """The `safety.evidence` response body: everything a peer may know
        about this system's Layer 1 relationship, and nothing it may change."""
        controller = self.driver.describe() if self.driver is not None else {"real_hardware": False, "integrity_claim": "no safety controller configured"}
        return {
            "type": "safety.evidence",
            "layer": int(Layer.L1_SAFETY),
            "observed_only": True,
            "controller": controller,
            "declared_functions": [function.to_dict() for function in self.functions],
            "status": self.status(),
            "poll_failures": self._poll_failures,
            "note": "FASP observes these functions and may request a halt. It does not implement, verify, or clear any of them.",
        }
