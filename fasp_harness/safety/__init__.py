"""Layer 1 as seen from Layer 3: observation, escalation, and honesty.

Nothing in this package is a safety function. That sentence is the design.
A safety function is a certified device with an assessed architecture, a
proof-tested failure rate, and an authority that survives this process
being killed. What lives here is the *supervisory* side of that
relationship:

- `SafetySupervisor` -- observes a real safety controller through a driver,
  latches a halt request, escalates, and refuses to be the thing that
  clears it.
- `drivers` -- how the observation actually happens: Modbus/TCP to a safety
  PLC, or a deterministic simulator for CI and hardware-in-the-loop.
- `case` -- a machine-checkable safety case: claims bound to evidence that
  is *executed*, so "we are safe" degrades into a list of which specific
  claims are currently supported and which are not.
"""

from __future__ import annotations

from .case import Claim, Evidence, EvidenceResult, SafetyCase, SafetyCaseReport
from .drivers import SafetyControllerDriver, SafetyStatus, SimulatedSafetyController
from .interlock import SafetyDemand, SafetyFunction, SafetySupervisor

__all__ = [
    "Claim",
    "Evidence",
    "EvidenceResult",
    "SafetyCase",
    "SafetyCaseReport",
    "SafetyControllerDriver",
    "SafetyDemand",
    "SafetyFunction",
    "SafetyStatus",
    "SafetySupervisor",
    "SimulatedSafetyController",
]
