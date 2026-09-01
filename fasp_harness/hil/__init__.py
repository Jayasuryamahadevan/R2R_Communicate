"""Hardware-in-the-loop: measure the response, do not describe it.

The claim that matters about a safety-adjacent system is a number with a
bound: "an E-stop demand produces an observed stop within N milliseconds,
measured M times, worst case W". You cannot get that from a unit test,
because a unit test asserts about a mock, and you cannot get it from a
document, because a document does not measure anything.

`HilBench` runs a scenario against a `DeviceUnderTest`: apply a stimulus,
poll until the expectation holds, record the latency, compare it against
the step's declared deadline. The DUT is an interface, so the *same*
scenario runs against a simulator in CI and against real hardware on a
bench -- and the report says which one it ran against, so a simulated pass
can never be mistaken for a hardware result.

The output is a signed, hash-chained evidence bundle. That is what the
safety case consumes: `SafetyCase` evidence for a response-time claim is
literally a run of one of these scenarios, so the claim cannot drift from
the measurement.
"""

from __future__ import annotations

from .bench import DeviceUnderTest, HilBench, HilReport, SimulatedSafetyDut, StepResult
from .scenario import Scenario, Step, standard_safety_scenarios

__all__ = ["DeviceUnderTest", "HilBench", "HilReport", "Scenario", "SimulatedSafetyDut", "Step", "StepResult", "standard_safety_scenarios"]
