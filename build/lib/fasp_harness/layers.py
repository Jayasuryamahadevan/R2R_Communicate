"""The FASP layer model, and the one invariant the whole system is built on.

FASP is a *coordination* protocol. It is not, and must never become, a
control system. That distinction is not a documentation nicety -- it is the
difference between a network fault degrading throughput and a network fault
degrading safety. This module makes it a checked property of the running
process rather than a claim in a README.

    Layer 1  hard real-time local safety
             E-stop, safety-rated lidar zones, speed/force limiting,
             safety PLC logic, motor control loops.
             Runs on certified hardware and/or a real-time kernel, OUTSIDE
             this process, with an authority that survives this process
             being killed, partitioned, or compromised.

    Layer 2  local autonomy
             Navigation, perception, obstacle avoidance, route following.
             Runs on the vehicle. FASP may OBSERVE it and may REQUEST a
             halt; FASP may hand it goal-level work; FASP never closes one
             of its control loops.

    Layer 3  fleet coordination
             Mission assignment, zone/space-time reservation, charging,
             task scheduling, traffic arbitration.  <-- FASP lives here.

    Layer 4  enterprise / cloud coordination
             WMS, MES, ERP, digital twin, analytics, human approvals.
                                                    <-- and here.

Two rules follow, and both are enforced below:

1. `PERMITTED_INTERACTIONS` -- what FASP is allowed to *do* to each layer.
   Toward Layer 1 the only permitted verb is OBSERVE. There is deliberately
   no code path in this repository through which a network peer can write
   to a Layer 1 function, and `LayerGuard` is what keeps it that way as the
   code changes.

2. `RESERVED_L1_FUNCTIONS` -- a semantic deny list. Rule 1 trusts the
   declared layer of a capability, and a declaration is exactly the thing a
   mistake (or an attacker with commit access) gets wrong. So capabilities
   whose *meaning* is a Layer 1 function are refused regardless of what
   layer they claim to be, and regardless of the risk class or grants
   attached to them.

`LayerGuard.validate_adapter()` runs at construction time, before the
harness binds a socket: an adapter that exposes a Layer 1 function fails
startup rather than failing an audit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .protocol.errors import FaspError

__all__ = [
    "Layer",
    "Interaction",
    "LayerViolation",
    "LayerGuard",
    "CapabilityDeclaration",
    "PERMITTED_INTERACTIONS",
    "RESERVED_L1_FUNCTIONS",
    "FASP_LAYERS",
    "describe_layers",
]


class Layer(IntEnum):
    """Where a function executes. Ordered so `<=` reads as "at or below"."""

    L1_SAFETY = 1
    L2_AUTONOMY = 2
    L3_FLEET = 3
    L4_ENTERPRISE = 4

    @property
    def title(self) -> str:
        return {
            Layer.L1_SAFETY: "hard real-time local safety",
            Layer.L2_AUTONOMY: "local autonomy",
            Layer.L3_FLEET: "fleet coordination",
            Layer.L4_ENTERPRISE: "enterprise/cloud coordination",
        }[self]

    @classmethod
    def parse(cls, value: Any) -> Layer:
        if isinstance(value, Layer):
            return value
        if isinstance(value, int) and value in {1, 2, 3, 4}:
            return cls(value)
        if isinstance(value, str):
            text = value.strip().upper().replace("-", "_")
            for member in cls:
                if text in {member.name, member.name.split("_")[0], str(member.value)}:
                    return member
        raise FaspError("schema.invalid", "Capability declares an unknown layer.")


class Interaction(IntEnum):
    """What FASP is doing to a layer, ordered by how much authority it takes."""

    OBSERVE = 1
    """Read state. Never changes anything. Safe toward every layer."""

    REQUEST_HALT = 2
    """Ask a machine to stop. Always safe to honour immediately, and never
    reversible over the network -- clearing a halt is local-only work."""

    COORDINATE = 3
    """Grant/deny a shared resource: a space-time reservation, a charger, a
    dock. Constrains what a vehicle is *permitted* to do; commands nothing."""

    DISPATCH = 4
    """Hand over goal-level work ("go to dock 7 and pick tote 42"). The
    receiving autonomy stack decides how, and remains free to refuse."""

    CONFIGURE = 5
    """Change parameters that outlive one mission."""

    ACTUATE = 6
    """Close a control loop: motor setpoints, joint targets, brake release,
    safety-zone muting. FASP never does this at any layer."""


# What FASP may do to each layer. Note ACTUATE appears nowhere: this
# protocol has no actuation verb at all, by construction.
PERMITTED_INTERACTIONS: dict[Layer, frozenset[Interaction]] = {
    Layer.L1_SAFETY: frozenset({Interaction.OBSERVE}),
    Layer.L2_AUTONOMY: frozenset({Interaction.OBSERVE, Interaction.REQUEST_HALT, Interaction.COORDINATE, Interaction.DISPATCH}),
    Layer.L3_FLEET: frozenset({Interaction.OBSERVE, Interaction.REQUEST_HALT, Interaction.COORDINATE, Interaction.DISPATCH, Interaction.CONFIGURE}),
    Layer.L4_ENTERPRISE: frozenset({Interaction.OBSERVE, Interaction.REQUEST_HALT, Interaction.COORDINATE, Interaction.DISPATCH, Interaction.CONFIGURE}),
}

# Semantic deny list (rule 2). Matched against a capability id, case
# insensitively, as whole dot-separated segments -- so `safety.estop.clear`
# and `x.safety.estop.clear.v2` both match, while `observe.estop.state`
# does not. Each entry names a function whose authority MUST come from
# certified local hardware, never from a signed network message.
RESERVED_L1_FUNCTIONS: tuple[tuple[str, str], ...] = (
    (r"estop\.(clear|reset|release|override|bypass|mute|inhibit)", "Clearing or bypassing an emergency stop is local, physical, certified work."),
    (r"(safety|protective)[._](zone|field|scanner|laser|curtain|mat)[._](mute|bypass|disable|override|clear|shrink)", "Muting or shrinking a safety-rated protective field is a Layer 1 safety function."),
    (r"(speed|force|torque|power)[._]?limit[._](override|disable|raise|bypass|increase)", "Speed/force limiting is a Layer 1 safety function."),
    (r"(motor|servo|drive|actuator|joint|wheel|axis)[._](command|setpoint|velocity|torque|current|enable|energize|jog|move)", "Closing a motor/servo control loop is Layer 1."),
    (r"brake[._](release|disengage|open)", "Brake release is a Layer 1 safety function."),
    (r"interlock[._](bypass|defeat|disable|override)", "Defeating an interlock is a Layer 1 safety function."),
    (r"watchdog[._](disable|extend|defeat|stop)", "Disabling a safety watchdog is a Layer 1 safety function."),
    (r"safe[._]?(stop|torque[._]?off|sto|ss1|ss2)[._](disable|bypass|override)", "Defeating a safe-stop function is Layer 1."),
    (r"(firmware|plc)[._](flash|program|download|write)", "Reprogramming a safety controller is out-of-band, authenticated, local engineering work."),
)

_RESERVED = tuple((re.compile(rf"(?:^|[._-]){pattern}(?:$|[._-])", re.IGNORECASE), reason) for pattern, reason in RESERVED_L1_FUNCTIONS)

FASP_LAYERS: frozenset[Layer] = frozenset({Layer.L3_FLEET, Layer.L4_ENTERPRISE})
"""The layers FASP itself implements. Everything else it only talks to."""


class LayerViolation(FaspError):
    """A capability, message, or adapter tried to cross the layer boundary.

    A `FaspError` so it is safe to surface to a peer and is handled by the
    existing transport error mapping, with its own code so an operator can
    alert on it distinctly from an ordinary authorization failure.
    """

    def __init__(self, detail: str) -> None:
        super().__init__("policy.layer_violation", detail)


@dataclass(frozen=True)
class CapabilityDeclaration:
    """One adapter capability, with the layer metadata FASP needs to police.

    Adapters written before this module existed simply omit `layer` and
    `interaction`; `from_mapping` infers a conservative default (observe at
    Layer 3) rather than failing, so the guard is additive to existing
    adapters instead of a breaking change -- but an inferred declaration
    can never be used to reach a lower layer, because inference never
    produces a layer below L3.
    """

    id: str
    risk: str = "observe"
    layer: Layer = Layer.L3_FLEET
    interaction: Interaction = Interaction.OBSERVE
    max_runtime_s: float = 5.0
    declared: bool = False
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, item: Any) -> CapabilityDeclaration:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise FaspError("schema.invalid", "Adapter capability requires a string id.")
        declared = "layer" in item or "interaction" in item
        layer = Layer.parse(item["layer"]) if "layer" in item else Layer.L3_FLEET
        interaction = _parse_interaction(item.get("interaction"))
        runtime = item.get("max_runtime_s", 5.0)
        return cls(
            id=item["id"],
            risk=str(item.get("risk", "observe")),
            layer=layer,
            interaction=interaction,
            max_runtime_s=float(runtime) if isinstance(runtime, (int, float)) and runtime > 0 else 5.0,
            declared=declared,
            raw=item,
        )


def _parse_interaction(value: Any) -> Interaction:
    if value is None:
        return Interaction.OBSERVE
    if isinstance(value, Interaction):
        return value
    if isinstance(value, str):
        try:
            return Interaction[value.strip().upper().replace("-", "_").replace(".", "_")]
        except KeyError as exc:
            raise FaspError("schema.invalid", "Capability declares an unknown interaction.") from exc
    raise FaspError("schema.invalid", "Capability declares an unknown interaction.")


class LayerGuard:
    """Enforces both layer rules, at startup and on every dispatch.

    Deliberately stateless and cheap: `check_capability` is on the hot path
    for every `intent.propose`, and a guard that is expensive to consult is
    a guard someone eventually caches away.
    """

    def __init__(self, *, allow_layer2_dispatch: bool = True) -> None:
        # A deployment that has not yet validated its Layer 2 integration
        # can start in observe-only mode: FASP will coordinate and observe,
        # but refuse to hand any vehicle goal-level work.
        self.allow_layer2_dispatch = allow_layer2_dispatch

    @staticmethod
    def reserved_reason(capability_id: str) -> str | None:
        """Return why `capability_id` names a Layer 1 function, or None."""
        for pattern, reason in _RESERVED:
            if pattern.search(capability_id):
                return reason
        return None

    def check_capability(self, declaration: CapabilityDeclaration) -> None:
        reason = self.reserved_reason(declaration.id)
        if reason is not None:
            raise LayerViolation(f"{declaration.id!r} names a Layer 1 safety function. {reason} FASP cannot carry it at any layer or risk class.")
        permitted = PERMITTED_INTERACTIONS[declaration.layer]
        if declaration.interaction not in permitted:
            allowed = ", ".join(sorted(item.name.lower() for item in permitted))
            raise LayerViolation(
                f"{declaration.id!r} declares {declaration.interaction.name.lower()} at Layer {declaration.layer.value} "
                f"({declaration.layer.title}); only {allowed} is permitted there."
            )
        if declaration.interaction is Interaction.DISPATCH and declaration.layer is Layer.L2_AUTONOMY and not self.allow_layer2_dispatch:
            raise LayerViolation(f"{declaration.id!r} dispatches to Layer 2, which this deployment has not enabled.")

    def validate_adapter(self, capabilities: list[dict[str, Any]]) -> list[CapabilityDeclaration]:
        """Validate every capability an adapter exposes. Raises on the first
        violation; returns the parsed declarations otherwise."""
        declarations = [CapabilityDeclaration.from_mapping(item) for item in capabilities]
        seen: set[str] = set()
        for declaration in declarations:
            if declaration.id in seen:
                raise FaspError("schema.invalid", f"Adapter declares capability {declaration.id!r} twice.")
            seen.add(declaration.id)
            self.check_capability(declaration)
        return declarations


def describe_layers() -> list[dict[str, Any]]:
    """Machine-readable layer model, published in the signed ID card.

    A peer can therefore see, before it sends anything, which layers this
    system implements and which it only observes -- rather than inferring
    it from whichever capabilities happen to be enabled today.
    """
    return [
        {
            "layer": layer.value,
            "title": layer.title,
            "implemented_here": layer in FASP_LAYERS,
            "permitted_interactions": sorted(item.name.lower() for item in PERMITTED_INTERACTIONS[layer]),
        }
        for layer in Layer
    ]
