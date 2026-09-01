"""The bench: apply, poll, measure, and produce evidence that can be checked.

Three details make the difference between a bench and a script.

**The clock starts at the stimulus, not at the first poll.** Latency is
measured from `perf_counter_ns()` immediately before the stimulus is
applied to the moment the expectation first holds, so the poll interval
contributes measurement *granularity* (bounded and reported) rather than a
systematic offset.

**The device is an interface.** The same scenario runs against
`SimulatedSafetyDut` in CI and against a real safety controller on a bench.
`HilReport.real_hardware` records which, so a green CI run can never be
presented as a hardware qualification.

**The report is hash-chained and signable.** Each step's record includes the
digest of the previous one, so a bundle cannot be edited after the fact
without detection, and an identity can sign the head. This is what the
safety case consumes as evidence for a response-time claim.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..crypto.canonical import canonicalize
from ..protocol.errors import FaspError
from ..safety.drivers import SafetyControllerDriver, SimulatedSafetyController
from ..safety.interlock import LOCAL_OPERATOR, SafetySupervisor
from ..timestamps import stamp
from .scenario import Sample, Scenario, Step

GENESIS = "fasp-hil-genesis"


@runtime_checkable
class DeviceUnderTest(Protocol):
    """What a bench needs from whatever it is testing."""

    def apply(self, command: dict[str, Any]) -> None:
        """Apply a stimulus. Physical on a bench, modelled in simulation."""
        ...

    def sample(self) -> Sample:
        """Observe the device now. Must be cheap: it is polled in a loop."""
        ...

    def describe(self) -> dict[str, Any]:
        """Identity of the device, including whether it is real hardware."""
        ...

    def reset(self) -> None: ...


@dataclass
class StepResult:
    step: Step
    passed: bool
    latency_ms: float | None
    detail: str
    samples: int
    at: str = field(default_factory=stamp)
    row_hash: str = ""
    prev_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step.name,
            "passed": self.passed,
            "latency_ms": round(self.latency_ms, 3) if self.latency_ms is not None else None,
            "deadline_ms": self.step.deadline_ms,
            "detail": self.detail,
            "samples": self.samples,
            "at": self.at,
            "prev_hash": self.prev_hash,
            "row_hash": self.row_hash,
        }


@dataclass
class HilReport:
    """One scenario run, with its measurements and its provenance."""

    scenario: str
    device: dict[str, Any]
    results: list[StepResult]
    poll_interval_ms: float
    started_at: str
    finished_at: str
    signature: dict[str, Any] | None = None

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(result.passed for result in self.results)

    @property
    def real_hardware(self) -> bool:
        return bool(self.device.get("real_hardware", False))

    @property
    def worst_latency_ms(self) -> float:
        return max((result.latency_ms or 0.0) for result in self.results) if self.results else 0.0

    def verify_chain(self) -> tuple[bool, int | None]:
        """Recompute every step's hash. Returns (ok, first_bad_index)."""
        previous = GENESIS
        for index, result in enumerate(self.results):
            expected = _row_hash(previous, result)
            if result.prev_hash != previous or result.row_hash != expected:
                return False, index
            previous = result.row_hash
        return True, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "passed": self.passed,
            "real_hardware": self.real_hardware,
            "device": self.device,
            "poll_interval_ms": self.poll_interval_ms,
            "measurement_granularity_ms": self.poll_interval_ms,
            "worst_latency_ms": round(self.worst_latency_ms, 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "steps": [result.to_dict() for result in self.results],
            "signature": self.signature,
            "note": "Simulated runs demonstrate logic and integration only. A timing claim about a machine requires this scenario on that machine's own hardware.",
        }

    def render_text(self) -> str:
        lines = [f"HIL scenario: {self.scenario}", f"device: {self.device.get('device', self.device.get('model', 'unknown'))} (real hardware: {self.real_hardware})", ""]
        for result in self.results:
            latency = f"{result.latency_ms:7.1f}ms" if result.latency_ms is not None else "     --  "
            lines.append(f"{'[ok]  ' if result.passed else '[FAIL]'} {latency} / {result.step.deadline_ms:.0f}ms  {result.step.name}: {result.detail}")
        lines += ["", f"VERDICT: {'pass' if self.passed else 'FAIL'} (worst {self.worst_latency_ms:.1f}ms, granularity {self.poll_interval_ms:.1f}ms)"]
        return "\n".join(lines)


def _row_hash(previous: str, result: StepResult) -> str:
    payload = canonicalize(
        {
            "prev": previous,
            "step": result.step.name,
            "passed": result.passed,
            "latency_ms": round(result.latency_ms, 3) if result.latency_ms is not None else None,
            "deadline_ms": result.step.deadline_ms,
            "samples": result.samples,
            "at": result.at,
        }
    )
    return hashlib.sha256(payload).hexdigest()


class HilBench:
    """Runs scenarios against a device and produces evidence."""

    def __init__(self, device: DeviceUnderTest, *, poll_interval_ms: float = 2.0, identity: Any = None) -> None:
        if poll_interval_ms <= 0:
            raise FaspError("schema.invalid", "poll_interval_ms must be positive.")
        self.device = device
        self.poll_interval_ms = poll_interval_ms
        self.identity = identity

    def run(self, scenario: Scenario) -> HilReport:
        started = stamp()
        results: list[StepResult] = []
        previous = GENESIS
        if scenario.setup is not None:
            scenario.setup(self.device)
        try:
            for step in scenario.steps:
                result = self._run_step(step)
                result.prev_hash = previous
                result.row_hash = previous = _row_hash(previous, result)
                results.append(result)
                if not result.passed and step.critical:
                    break
        finally:
            if scenario.teardown is not None:
                scenario.teardown(self.device)

        report = HilReport(
            scenario=scenario.name,
            device=self.device.describe(),
            results=results,
            poll_interval_ms=self.poll_interval_ms,
            started_at=started,
            finished_at=stamp(),
        )
        if self.identity is not None and results:
            report.signature = self._sign(results[-1].row_hash, report)
        return report

    def _run_step(self, step: Step) -> StepResult:
        if step.settle_ms:
            time.sleep(step.settle_ms / 1000.0)
        deadline_ns = int(step.deadline_ms * 1_000_000)
        # The clock starts here, before the stimulus, so nothing the
        # stimulus itself costs is excluded from the measurement.
        started_ns = time.perf_counter_ns()
        if step.stimulus is not None:
            try:
                step.stimulus(self.device)
            except Exception as exc:  # noqa: BLE001 - a failed stimulus is a failed step, not a crashed bench
                return StepResult(step, False, None, f"stimulus raised {exc.__class__.__name__}", 0)

        samples = 0
        while True:
            try:
                sample = self.device.sample()
                samples += 1
                satisfied = bool(step.expect(sample))
            except Exception as exc:  # noqa: BLE001 - see above
                return StepResult(step, False, None, f"expectation raised {exc.__class__.__name__}", samples)
            elapsed_ns = time.perf_counter_ns() - started_ns
            if satisfied:
                latency_ms = elapsed_ns / 1e6
                within = elapsed_ns <= deadline_ns
                return StepResult(step, within, latency_ms, "met within deadline" if within else f"met after {latency_ms:.1f}ms, past the {step.deadline_ms:.0f}ms budget", samples)
            if elapsed_ns > deadline_ns:
                return StepResult(step, False, None, f"expectation never held within {step.deadline_ms:.0f}ms ({samples} samples)", samples)
            time.sleep(self.poll_interval_ms / 1000.0)

    def _sign(self, head: str, report: HilReport) -> dict[str, Any]:
        from ..crypto.envelope import sign

        return sign({"type": "hil.evidence", "scenario": report.scenario, "head": head, "passed": report.passed, "real_hardware": report.real_hardware, "at": report.finished_at}, self.identity.private, self.identity.kid)

    def run_all(self, scenarios: list[Scenario]) -> list[HilReport]:
        return [self.run(scenario) for scenario in scenarios]


class SimulatedSafetyDut:
    """A DUT wiring a simulated safety controller to a real supervisor.

    Note what is and is not simulated. The controller is a model; the
    `SafetySupervisor`, its staleness rule, its latch, and its refusal to be
    cleared over a network are the *actual production objects*. So these
    scenarios test the real supervisory logic, and only the physics of the
    contactor is stand-in. Swapping in `ModbusSafetyController` against a
    real PLC changes one constructor argument.
    """

    def __init__(self, *, stop_delay_s: float = 0.0, stale_after_s: float = 0.5) -> None:
        self.controller = SimulatedSafetyController(stop_delay_s=stop_delay_s)
        self.supervisor = SafetySupervisor(self.controller, stale_after_s=stale_after_s)
        self.moving = False
        self.rejected_network_clears = 0

    def apply(self, command: dict[str, Any]) -> None:
        if "estop" in command:
            self.controller.press_estop() if command["estop"] else self.controller.release_estop()
        if "zone" in command:
            self.controller.set_zone_violated(bool(command["zone"]))
        if "guard_open" in command:
            self.controller.set_guard_open(bool(command["guard_open"]))
        if "unreachable" in command:
            self.controller.set_unreachable(bool(command["unreachable"]))
        if command.get("network_halt"):
            self.supervisor.demand_halt("hil-bench", str(command["network_halt"]), origin="peer")
        if command.get("network_clear"):
            # The bench asserts the refusal rather than assuming it: a
            # LayerViolation here is the expected, correct outcome.
            try:
                self.supervisor.clear(origin="peer", operator="remote-peer")
            except FaspError:
                self.rejected_network_clears += 1
        if command.get("reset"):
            self.controller.manual_reset()
            try:
                self.supervisor.clear(origin=LOCAL_OPERATOR, operator="bench-operator")
            except FaspError:
                pass
        if "moving" in command:
            self.moving = bool(command["moving"])

    def sample(self) -> Sample:
        status = self.supervisor.poll()
        permitted, reason = self.supervisor.permitted(requested_speed_mps=0.0, reservation_active=True)
        return {
            "safe_to_move": permitted,
            "reason": reason,
            "moving": self.moving,
            "estop_clear": status.estop_clear,
            "reachable": status.reachable,
            "reset_required": status.reset_required or self.supervisor.latched,
            "latched": self.supervisor.latched,
        }

    def describe(self) -> dict[str, Any]:
        return {**self.controller.describe(), "supervisor": "production SafetySupervisor", "rejected_network_clears": self.rejected_network_clears}

    def reset(self) -> None:
        self.controller.set_unreachable(False)
        self.controller.release_estop()
        self.controller.set_zone_violated(False)
        self.controller.set_guard_open(False)
        self.controller.manual_reset()
        try:
            self.supervisor.clear(origin=LOCAL_OPERATOR, operator="bench-reset")
        except FaspError:
            pass


def make_driver_dut(driver: SafetyControllerDriver, *, stale_after_s: float = 2.0) -> SimulatedSafetyDut:
    """Build a DUT around any driver, including a real Modbus safety PLC."""
    dut = SimulatedSafetyDut(stale_after_s=stale_after_s)
    dut.supervisor = SafetySupervisor(driver, stale_after_s=stale_after_s)
    return dut
