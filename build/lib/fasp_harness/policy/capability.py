"""Capability risk-class policy (FASP_PROTOCOL.md ss8).

Centralizes the "which risk classes will this reference harness execute at
all" decision so it isn't buried inline in the task-handling code path.
"""

from __future__ import annotations

# Risk classes this harness executes without a local confirmation/safety-
# controller mechanism it doesn't implement. Per ss8's table, everything
# from bounded-actuate upward needs a lease/interlock/principal-grant/
# certified safety controller this reference harness's DefaultSafeAdapter
# does not provide, so those risk classes are rejected outright rather
# than half-supported.
EXECUTABLE_RISK_CLASSES = frozenset({"observe", "reversible"})

# Risk classes that MUST be backed by an explicit, currently-valid grant
# (fasp_harness.policy.grants) rather than just the peer's pairing-time
# capability prefixes, per ss3.3: "Pairing MUST require a human or an
# existing trusted issuer for any capability above observe.*."
GRANT_REQUIRED_RISK_CLASSES = frozenset({"reversible"})


def is_executable(risk: str) -> bool:
    return risk in EXECUTABLE_RISK_CLASSES


def requires_grant(risk: str) -> bool:
    return risk in GRANT_REQUIRED_RISK_CLASSES
