"""ROS 2 done the way production requires: lifecycle, QoS, and SROS 2.

Three things separate a ROS 2 integration that survives a factory from one
that survives a demo, and all three are usually skipped:

**Lifecycle.** A production node is a *managed* node. It has a defined
state machine, it does not allocate or publish until configured, and an
orchestrator can bring a subsystem up and down deterministically. Getting
this wrong looks like a node that publishes stale data during startup, or
one that cannot be restarted without restarting everything. The state
machine here is the one from the ROS 2 managed-node design, including the
transition states and the error-handling path, so it can be driven and
tested without a ROS installation.

**QoS.** DDS silently does not connect a publisher and a subscriber whose
qualities of service are incompatible. No error, no warning -- just a topic
that is never received, discovered hours later. `QosProfile.compatible_with`
implements the actual Requested-vs-Offered rules, so an integration can
check compatibility up front and say precisely which policy is the problem.

**Security.** ROS 2 without SROS 2 is an unauthenticated bus: any process
that can reach the DDS domain can publish anything, including to
`/cmd_vel`. On a robot that is not a configuration weakness, it is the
whole attack. `Sros2Posture` inspects the actual environment and keystore
and, in a production profile, refuses to run when security is off or merely
permissive.

None of this imports `rclpy`. The state machine, the QoS rules, and the
posture checks are pure logic and stay testable in CI on a machine with no
ROS at all; `fasp_harness/ros2_adapter.py` is where the optional binding to
a live graph lives.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any

from ..protocol.errors import FaspError


# --------------------------------------------------------------------------
# Managed-node lifecycle
# --------------------------------------------------------------------------
class LifecycleState(StrEnum):
    UNKNOWN = "unknown"
    UNCONFIGURED = "unconfigured"
    INACTIVE = "inactive"
    ACTIVE = "active"
    FINALIZED = "finalized"
    CONFIGURING = "configuring"
    CLEANINGUP = "cleaningup"
    SHUTTINGDOWN = "shuttingdown"
    ACTIVATING = "activating"
    DEACTIVATING = "deactivating"
    ERRORPROCESSING = "errorprocessing"

    @property
    def primary(self) -> bool:
        return self in {LifecycleState.UNCONFIGURED, LifecycleState.INACTIVE, LifecycleState.ACTIVE, LifecycleState.FINALIZED}


class Transition(StrEnum):
    CONFIGURE = "configure"
    CLEANUP = "cleanup"
    ACTIVATE = "activate"
    DEACTIVATE = "deactivate"
    SHUTDOWN = "shutdown"
    DESTROY = "destroy"


class CallbackReturn(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


# (from-state, transition) -> (transition-state, on-success, on-failure)
_TRANSITIONS: dict[tuple[LifecycleState, Transition], tuple[LifecycleState, LifecycleState, LifecycleState]] = {
    (LifecycleState.UNCONFIGURED, Transition.CONFIGURE): (LifecycleState.CONFIGURING, LifecycleState.INACTIVE, LifecycleState.UNCONFIGURED),
    (LifecycleState.INACTIVE, Transition.CLEANUP): (LifecycleState.CLEANINGUP, LifecycleState.UNCONFIGURED, LifecycleState.INACTIVE),
    (LifecycleState.INACTIVE, Transition.ACTIVATE): (LifecycleState.ACTIVATING, LifecycleState.ACTIVE, LifecycleState.INACTIVE),
    (LifecycleState.ACTIVE, Transition.DEACTIVATE): (LifecycleState.DEACTIVATING, LifecycleState.INACTIVE, LifecycleState.ACTIVE),
    (LifecycleState.UNCONFIGURED, Transition.SHUTDOWN): (LifecycleState.SHUTTINGDOWN, LifecycleState.FINALIZED, LifecycleState.FINALIZED),
    (LifecycleState.INACTIVE, Transition.SHUTDOWN): (LifecycleState.SHUTTINGDOWN, LifecycleState.FINALIZED, LifecycleState.FINALIZED),
    (LifecycleState.ACTIVE, Transition.SHUTDOWN): (LifecycleState.SHUTTINGDOWN, LifecycleState.FINALIZED, LifecycleState.FINALIZED),
}


class LifecycleError(FaspError):
    def __init__(self, detail: str) -> None:
        super().__init__("lifecycle.invalid_transition", detail)


@dataclass
class LifecycleEvent:
    transition: Transition
    start_state: LifecycleState
    goal_state: LifecycleState
    result: CallbackReturn
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"transition": self.transition.value, "start_state": self.start_state.value, "goal_state": self.goal_state.value, "result": self.result.value, "detail": self.detail}


class LifecycleNode:
    """The ROS 2 managed-node state machine, usable without ROS.

    Two behaviours are worth calling out, because both are the standard's
    and both surprise people:

    - a callback returning FAILURE returns the node to where it came from,
      while returning ERROR routes through `errorprocessing`. They are not
      the same thing: FAILURE is "I could not do that", ERROR is "I am now
      in an unknown state";
    - `errorprocessing` that itself fails ends in `finalized`, not back in
      `unconfigured`. A node that cannot clean up after its own error is
      not something to keep running.

    `on_activate`/`on_deactivate` are where a real node starts and stops
    publishing. A subsystem being INACTIVE is the difference between a
    coordinator that knows a sensor is not producing and one that is quietly
    consuming its last frame forever.
    """

    def __init__(self, name: str, *, callbacks: dict[Transition, Callable[[LifecycleState], CallbackReturn]] | None = None) -> None:
        self.name = name
        self.state = LifecycleState.UNCONFIGURED
        self.callbacks = dict(callbacks or {})
        self.history: list[LifecycleEvent] = []
        self.on_error: Callable[[LifecycleState], CallbackReturn] | None = None

    def available_transitions(self) -> list[Transition]:
        return sorted((transition for (state, transition) in _TRANSITIONS if state is self.state), key=lambda item: item.value)

    def trigger(self, transition: Transition) -> LifecycleState:
        """Attempt a transition. Raises only on an *invalid* one; a callback
        that fails is a normal, reported outcome, not an exception."""
        key = (self.state, transition)
        if key not in _TRANSITIONS:
            raise LifecycleError(f"Node {self.name!r} cannot {transition.value} from {self.state.value}; available: {[item.value for item in self.available_transitions()]}.")
        transition_state, on_success, on_failure = _TRANSITIONS[key]
        start_state = self.state
        self.state = transition_state
        callback = self.callbacks.get(transition)
        result = CallbackReturn.SUCCESS
        detail = ""
        if callback is not None:
            try:
                result = callback(start_state)
            except Exception as exc:  # noqa: BLE001 - a raising callback is an ERROR, not a crash
                result, detail = CallbackReturn.ERROR, f"callback raised {exc.__class__.__name__}"

        if result is CallbackReturn.SUCCESS:
            self.state = on_success
        elif result is CallbackReturn.FAILURE:
            self.state = on_failure
        else:
            self.state = self._process_error(start_state)
        self.history.append(LifecycleEvent(transition, start_state, self.state, result, detail))
        return self.state

    def _process_error(self, start_state: LifecycleState) -> LifecycleState:
        self.state = LifecycleState.ERRORPROCESSING
        if self.on_error is None:
            return LifecycleState.UNCONFIGURED
        try:
            outcome = self.on_error(start_state)
        except Exception:  # noqa: BLE001 - error handling that itself throws is terminal
            return LifecycleState.FINALIZED
        return LifecycleState.UNCONFIGURED if outcome is CallbackReturn.SUCCESS else LifecycleState.FINALIZED

    @property
    def publishing(self) -> bool:
        """A managed node publishes only while ACTIVE. This is the property
        the whole state machine exists to make true."""
        return self.state is LifecycleState.ACTIVE

    def bring_up(self) -> LifecycleState:
        """configure + activate, the ordinary startup path."""
        self.trigger(Transition.CONFIGURE)
        if self.state is LifecycleState.INACTIVE:
            self.trigger(Transition.ACTIVATE)
        return self.state

    def shut_down(self) -> LifecycleState:
        if self.state.primary and self.state is not LifecycleState.FINALIZED:
            self.trigger(Transition.SHUTDOWN)
        return self.state

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "state": self.state.value, "publishing": self.publishing, "available": [item.value for item in self.available_transitions()], "history": [event.to_dict() for event in self.history[-10:]]}


class LifecycleManager:
    """Bring an ordered set of nodes up and down as one subsystem.

    Ordering matters and is the caller's: perception before navigation,
    navigation before mission execution. Bring-up stops at the first node
    that will not activate and reports which one, instead of leaving a
    half-started system that looks running.
    """

    def __init__(self) -> None:
        self.nodes: list[LifecycleNode] = []

    def add(self, node: LifecycleNode) -> LifecycleNode:
        self.nodes.append(node)
        return node

    def bring_up(self) -> tuple[bool, list[dict[str, Any]]]:
        report: list[dict[str, Any]] = []
        for node in self.nodes:
            state = node.bring_up()
            report.append({"node": node.name, "state": state.value})
            if state is not LifecycleState.ACTIVE:
                return False, report
        return True, report

    def shut_down(self) -> list[dict[str, Any]]:
        # Reverse order: a consumer stops before the thing it consumes.
        return [{"node": node.name, "state": node.shut_down().value} for node in reversed(self.nodes)]

    def all_active(self) -> bool:
        return bool(self.nodes) and all(node.state is LifecycleState.ACTIVE for node in self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {"all_active": self.all_active(), "nodes": [node.to_dict() for node in self.nodes]}


# --------------------------------------------------------------------------
# DDS quality of service
# --------------------------------------------------------------------------
class Reliability(StrEnum):
    BEST_EFFORT = "best_effort"
    RELIABLE = "reliable"


class Durability(StrEnum):
    VOLATILE = "volatile"
    TRANSIENT_LOCAL = "transient_local"


class Liveliness(StrEnum):
    AUTOMATIC = "automatic"
    MANUAL_BY_TOPIC = "manual_by_topic"


class History(StrEnum):
    KEEP_LAST = "keep_last"
    KEEP_ALL = "keep_all"


@dataclass(frozen=True)
class QosProfile:
    """A DDS QoS profile, with real Requested-vs-Offered compatibility."""

    reliability: Reliability = Reliability.RELIABLE
    durability: Durability = Durability.VOLATILE
    history: History = History.KEEP_LAST
    depth: int = 10
    deadline_s: float | None = None
    lifespan_s: float | None = None
    liveliness: Liveliness = Liveliness.AUTOMATIC
    lease_duration_s: float | None = None

    def compatible_with(self, offered: QosProfile) -> tuple[bool, list[str]]:
        """Can this (requested, i.e. subscriber) profile receive `offered`?

        The DDS rule is that the offered quality must be at least as strong
        as the requested one. Returns every incompatibility, not just the
        first: an integrator fixing these one round trip at a time is how a
        morning disappears.
        """
        problems: list[str] = []
        if self.reliability is Reliability.RELIABLE and offered.reliability is Reliability.BEST_EFFORT:
            problems.append("Subscriber requests RELIABLE but the publisher offers BEST_EFFORT.")
        if self.durability is Durability.TRANSIENT_LOCAL and offered.durability is Durability.VOLATILE:
            problems.append("Subscriber requests TRANSIENT_LOCAL but the publisher offers VOLATILE, so late joiners receive nothing.")
        if self.deadline_s is not None and (offered.deadline_s is None or offered.deadline_s > self.deadline_s):
            problems.append(f"Subscriber requests a {self.deadline_s}s deadline but the publisher offers {offered.deadline_s}.")
        if self.liveliness is Liveliness.MANUAL_BY_TOPIC and offered.liveliness is Liveliness.AUTOMATIC:
            problems.append("Subscriber requests MANUAL_BY_TOPIC liveliness but the publisher offers AUTOMATIC.")
        if self.lease_duration_s is not None and (offered.lease_duration_s is None or offered.lease_duration_s > self.lease_duration_s):
            problems.append(f"Subscriber requests a {self.lease_duration_s}s liveliness lease but the publisher offers {offered.lease_duration_s}.")
        return not problems, problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "reliability": self.reliability.value,
            "durability": self.durability.value,
            "history": self.history.value,
            "depth": self.depth,
            "deadline_s": self.deadline_s,
            "lifespan_s": self.lifespan_s,
            "liveliness": self.liveliness.value,
            "lease_duration_s": self.lease_duration_s,
        }


# The profiles ROS 2 itself defines, plus one for supervisory telemetry.
SENSOR_DATA = QosProfile(reliability=Reliability.BEST_EFFORT, history=History.KEEP_LAST, depth=5)
SERVICES_DEFAULT = QosProfile(reliability=Reliability.RELIABLE, history=History.KEEP_LAST, depth=10)
PARAMETERS = QosProfile(reliability=Reliability.RELIABLE, history=History.KEEP_LAST, depth=1000)
SYSTEM_DEFAULT = QosProfile()
SUPERVISORY_STATUS = QosProfile(reliability=Reliability.RELIABLE, durability=Durability.TRANSIENT_LOCAL, depth=1, deadline_s=1.0, liveliness=Liveliness.AUTOMATIC, lease_duration_s=2.0)
"""Latched, deadline-bounded status: a late-joining coordinator gets the
current value immediately, and a publisher that stops publishing is
detected within the lease rather than assumed to still be fine."""


# --------------------------------------------------------------------------
# SROS 2 security posture
# --------------------------------------------------------------------------
@dataclass
class SecurityFinding:
    control: str
    severity: str
    detail: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"control": self.control, "severity": self.severity, "detail": self.detail, "remediation": self.remediation}


@dataclass
class Sros2Posture:
    """What ROS 2 security is actually configured to do on this host."""

    enabled: bool
    enforcing: bool
    keystore: str | None
    enclave: str | None
    findings: list[SecurityFinding] = field(default_factory=list)

    @property
    def acceptable_for_production(self) -> bool:
        return self.enabled and self.enforcing and not [finding for finding in self.findings if finding.severity == "critical"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "enforcing": self.enforcing,
            "keystore": self.keystore,
            "enclave": self.enclave,
            "acceptable_for_production": self.acceptable_for_production,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def require_enforcing(self) -> None:
        if not self.acceptable_for_production:
            detail = "; ".join(finding.detail for finding in self.findings if finding.severity == "critical") or "ROS 2 security is not enabled and enforcing."
            raise FaspError("policy.insecure_configuration", f"Refusing to run a production profile on an unauthenticated ROS 2 domain: {detail}")


def inspect_sros2(environment: dict[str, str] | None = None) -> Sros2Posture:
    """Inspect SROS 2 configuration from the environment and the keystore.

    Checked, not assumed: `ROS_SECURITY_STRATEGY=Permit` is the setting that
    looks secure and is not -- a node with no enclave simply runs
    unauthenticated instead of failing. That is a critical finding here,
    because it is the configuration most often found in the field.
    """
    env = dict(os.environ if environment is None else environment)
    enabled = env.get("ROS_SECURITY_ENABLE", "false").strip().lower() == "true"
    strategy = env.get("ROS_SECURITY_STRATEGY", "Permit").strip().lower()
    enforcing = enabled and strategy == "enforce"
    keystore = env.get("ROS_SECURITY_KEYSTORE")
    enclave = env.get("ROS_SECURITY_ENCLAVE_OVERRIDE")
    findings: list[SecurityFinding] = []

    if not enabled:
        findings.append(
            SecurityFinding("sros2.enable", "critical", "ROS_SECURITY_ENABLE is not true: the DDS domain is unauthenticated, so any process that can reach it may publish to any topic.", "Set ROS_SECURITY_ENABLE=true and create a keystore with `ros2 security create_keystore`.")
        )
    elif not enforcing:
        findings.append(
            SecurityFinding("sros2.strategy", "critical", f"ROS_SECURITY_STRATEGY is {strategy!r}, not 'Enforce': a node without security material runs unauthenticated instead of failing to start.", "Set ROS_SECURITY_STRATEGY=Enforce.")
        )

    if enabled and not keystore:
        findings.append(SecurityFinding("sros2.keystore", "critical", "ROS_SECURITY_ENABLE is set but ROS_SECURITY_KEYSTORE names no keystore.", "Point ROS_SECURITY_KEYSTORE at the keystore directory."))
    elif keystore:
        findings.extend(_inspect_keystore(Path(keystore), enclave))

    if env.get("ROS_LOCALHOST_ONLY") == "1" and not enabled:
        findings.append(SecurityFinding("sros2.localhost_only", "medium", "ROS_LOCALHOST_ONLY limits exposure but is not authentication; anything on this host can still publish.", "Enable SROS 2 as well."))
    if not env.get("ROS_DOMAIN_ID"):
        findings.append(SecurityFinding("dds.domain", "low", "ROS_DOMAIN_ID is unset, so this node shares the default domain 0 with every other default node reachable on the network.", "Assign an explicit ROS_DOMAIN_ID per system."))

    return Sros2Posture(enabled=enabled, enforcing=enforcing, keystore=keystore, enclave=enclave, findings=findings)


def _inspect_keystore(keystore: Path, enclave: str | None) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    if not keystore.is_dir():
        return [SecurityFinding("sros2.keystore", "critical", "The configured ROS 2 keystore directory does not exist.", "Create it with `ros2 security create_keystore`.")]
    for required in ("public", "private", "enclaves"):
        if not (keystore / required).is_dir():
            findings.append(SecurityFinding("sros2.keystore", "high", f"Keystore is missing its {required!r} directory, so it is incomplete.", "Recreate the keystore."))
    private = keystore / "private"
    if private.is_dir():
        try:
            mode = private.stat().st_mode & 0o777
            if mode & 0o077:
                findings.append(SecurityFinding("sros2.keystore_permissions", "critical", f"Keystore private material is mode {mode:o}: readable beyond its owner.", "chmod 700 the private directory and 600 the key files."))
        except OSError:
            findings.append(SecurityFinding("sros2.keystore_permissions", "medium", "Keystore private directory permissions could not be read.", ""))
    if enclave:
        enclave_path = keystore / "enclaves" / enclave.strip("/")
        if not enclave_path.is_dir():
            findings.append(SecurityFinding("sros2.enclave", "critical", f"ROS_SECURITY_ENCLAVE_OVERRIDE names enclave {enclave!r}, which does not exist in the keystore.", "Create it with `ros2 security create_enclave`."))
        else:
            for artefact in ("cert.pem", "key.pem", "permissions.p7s", "governance.p7s"):
                if not (enclave_path / artefact).exists():
                    findings.append(SecurityFinding("sros2.enclave", "high", f"Enclave {enclave!r} is missing {artefact}.", "Regenerate the enclave's security artefacts."))
    return findings
