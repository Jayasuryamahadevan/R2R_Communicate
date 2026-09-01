"""Scenarios: stimulus, expectation, deadline. Nothing else.

A step is three things and a name. The stimulus does something to the
device; the expectation is a predicate over what the device reports; the
deadline is the budget the expectation must be met within. Keeping it that
narrow means a scenario is data -- reviewable by a safety engineer who does
not read Python closely, and identical whether it runs against a simulator
or a real machine.

`standard_safety_scenarios()` ships the checks any mobile-robot deployment
owes an assessor, written against the `DeviceUnderTest` interface so they
run in CI today and on a bench tomorrow with no edit.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Sample = dict[str, Any]


@dataclass(frozen=True)
class Step:
    """One stimulus and the response it must produce, in time."""

    name: str
    expect: Callable[[Sample], bool]
    stimulus: Callable[[Any], None] | None = None
    deadline_ms: float = 500.0
    settle_ms: float = 0.0
    description: str = ""
    critical: bool = True
    """A failed critical step aborts the scenario. Continuing past a failed
    safety expectation measures the behaviour of a system already in a state
    the scenario did not intend, which produces numbers that mean nothing."""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "deadline_ms": self.deadline_ms, "settle_ms": self.settle_ms, "description": self.description, "critical": self.critical}


@dataclass(frozen=True)
class Scenario:
    name: str
    steps: tuple[Step, ...]
    description: str = ""
    setup: Callable[[Any], None] | None = None
    teardown: Callable[[Any], None] | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "tags": list(self.tags), "steps": [step.to_dict() for step in self.steps]}


# -- predicates ------------------------------------------------------------
def stopped(sample: Sample) -> bool:
    return not sample.get("safe_to_move", False) and not sample.get("moving", False)


def moving_permitted(sample: Sample) -> bool:
    return bool(sample.get("safe_to_move", False))


def reset_required(sample: Sample) -> bool:
    return bool(sample.get("reset_required", False))


def standard_safety_scenarios() -> list[Scenario]:
    """The response-time and latching checks a deployment owes an assessor.

    Each one exists because its absence is a known field failure:

    - *estop response* is the headline number every assessor asks for.
    - *latching* catches the integration bug where releasing the button
      resumes motion. Releasing an E-stop is not a reset, and a system that
      treats it as one restarts a machine with a person still next to it.
    - *reset refusal* catches the opposite bug: a reset accepted while the
      demand is still present.
    - *unreachable controller* checks the fail-safe default. A coordinator
      that cannot see the safety controller must refuse motion, not assume
      the last good sample still holds.
    - *network halt request* checks that a Layer 3 halt is honoured, and
      that honouring it does not grant Layer 3 the ability to undo it.
    """
    return [
        Scenario(
            name="estop-response-time",
            description="A physical E-stop demand produces an observed stop within the declared budget.",
            tags=("safety", "timing"),
            steps=(
                Step("baseline-permits-motion", moving_permitted, lambda dut: dut.apply({"reset": True}), deadline_ms=1000.0, description="Start from a state where motion is permitted."),
                Step("estop-stops", stopped, lambda dut: dut.apply({"estop": True}), deadline_ms=250.0, description="Press E-stop; the observed state must become not-safe-to-move."),
            ),
        ),
        Scenario(
            name="estop-latching",
            description="Releasing the button does not resume motion; only a deliberate local reset does.",
            tags=("safety", "latching"),
            steps=(
                Step("estop-stops", stopped, lambda dut: dut.apply({"estop": True}), deadline_ms=250.0),
                Step("release-stays-stopped", stopped, lambda dut: dut.apply({"estop": False}), deadline_ms=250.0, settle_ms=50.0, description="Button released, demand gone -- the stop must remain latched."),
                Step("reset-required-reported", reset_required, None, deadline_ms=250.0),
                Step("local-reset-restores", moving_permitted, lambda dut: dut.apply({"reset": True}), deadline_ms=500.0, description="Only the local reset restores permission."),
            ),
        ),
        Scenario(
            name="reset-refused-under-demand",
            description="A reset attempted while the demand is still present is refused.",
            tags=("safety", "latching"),
            steps=(
                Step("estop-stops", stopped, lambda dut: dut.apply({"estop": True}), deadline_ms=250.0),
                Step("reset-refused", stopped, lambda dut: dut.apply({"reset": True}), deadline_ms=250.0, settle_ms=50.0, description="Reset with the button still pressed must not restore motion."),
            ),
        ),
        Scenario(
            name="controller-unreachable-fails-safe",
            description="Losing sight of the safety controller withdraws permission to move.",
            tags=("safety", "fail-safe"),
            steps=(
                Step("baseline-permits-motion", moving_permitted, lambda dut: dut.apply({"reset": True}), deadline_ms=1000.0),
                Step("unreachable-withdraws-permission", stopped, lambda dut: dut.apply({"unreachable": True}), deadline_ms=3000.0, description="No news must be treated as bad news."),
                Step("recovery-restores", moving_permitted, lambda dut: dut.apply({"unreachable": False, "reset": True}), deadline_ms=1000.0),
            ),
        ),
        Scenario(
            name="network-halt-request",
            description="A Layer 3 halt request is honoured, and cannot be undone from Layer 3.",
            tags=("safety", "layers"),
            steps=(
                Step("baseline-permits-motion", moving_permitted, lambda dut: dut.apply({"reset": True}), deadline_ms=1000.0),
                Step("network-halt-honoured", stopped, lambda dut: dut.apply({"network_halt": "requested by a paired peer"}), deadline_ms=500.0),
                Step("network-clear-refused", stopped, lambda dut: dut.apply({"network_clear": True}), deadline_ms=500.0, settle_ms=50.0, description="A network peer attempting to clear the halt must change nothing."),
            ),
        ),
    ]
