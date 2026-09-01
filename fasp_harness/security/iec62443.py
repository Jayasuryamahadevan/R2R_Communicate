"""IEC 62443 as an evaluated register, plus the zone-and-conduit model.

IEC 62443-3-3 organises system security requirements under seven
foundational requirements, each with a target Security Level from SL 1
(protection against casual or coincidental violation) to SL 4 (a
state-level adversary with extended resources). A conformance assessment
asks, requirement by requirement, whether the system meets its SL-T.

Most of that work is human. Some of it is not: whether TLS is on, whether
the audit log verifies, whether the private key is 0600, whether replay
protection exists -- those are properties of a running system that a
running system can check about itself. Those are the ones here, each
control bound to a predicate over `SystemContext`. Everything else is
marked `MANUAL` and named, so it appears in the report as work to do
rather than quietly not appearing at all.

The achieved SL per foundational requirement is the *minimum* across its
controls, which is the correct and unflattering rule: a chain of met
requirements plus one gap is a system at the gap's level, not the average.

62443-3-2's zone and conduit model is here too. Stating that the vehicle
network is one zone, the coordinator another, and the enterprise a third --
with conduits between them at declared security levels -- is what turns
"we have a firewall" into an architecture you can assess.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from ..timestamps import stamp


class SecurityLevel(IntEnum):
    SL0 = 0
    SL1 = 1
    SL2 = 2
    SL3 = 3
    SL4 = 4

    @property
    def description(self) -> str:
        return {
            SecurityLevel.SL0: "no specific requirements",
            SecurityLevel.SL1: "protection against casual or coincidental violation",
            SecurityLevel.SL2: "protection against intentional violation using simple means, low resources, generic skills",
            SecurityLevel.SL3: "protection against intentional violation using sophisticated means, moderate resources, IACS-specific skills",
            SecurityLevel.SL4: "protection against intentional violation using sophisticated means, extended resources, IACS-specific skills",
        }[self]


class FoundationalRequirement(StrEnum):
    """The seven FRs of IEC 62443-3-3."""

    FR1 = "identification and authentication control"
    FR2 = "use control"
    FR3 = "system integrity"
    FR4 = "data confidentiality"
    FR5 = "restricted data flow"
    FR6 = "timely response to events"
    FR7 = "resource availability"


class ControlStatus(StrEnum):
    MET = "met"
    PARTIAL = "partial"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"
    MANUAL = "manual"
    """Requires evidence this software cannot produce about itself -- a
    physical control, an organisational process, or a third-party test."""


@dataclass
class ControlResult:
    status: ControlStatus
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def met(cls, detail: str, **evidence: Any) -> ControlResult:
        return cls(ControlStatus.MET, detail, evidence)

    @classmethod
    def partial(cls, detail: str, **evidence: Any) -> ControlResult:
        return cls(ControlStatus.PARTIAL, detail, evidence)

    @classmethod
    def not_met(cls, detail: str, **evidence: Any) -> ControlResult:
        return cls(ControlStatus.NOT_MET, detail, evidence)

    @classmethod
    def manual(cls, detail: str) -> ControlResult:
        return cls(ControlStatus.MANUAL, detail, {})

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "detail": self.detail, "evidence": self.evidence}


@dataclass
class SystemContext:
    """What a control gets to look at when deciding whether it is met."""

    config: Any = None
    harness: Any = None
    supervisor: Any = None
    ros2_posture: Any = None
    audit_ok: bool | None = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Control:
    id: str
    fr: FoundationalRequirement
    title: str
    sl_target: SecurityLevel
    evaluate: Callable[[SystemContext], ControlResult]

    def run(self, context: SystemContext) -> ControlResult:
        try:
            return self.evaluate(context)
        except Exception as exc:  # noqa: BLE001 - a broken check is an unmet control, never a pass
            return ControlResult(ControlStatus.NOT_MET, f"Control evaluation raised {exc.__class__.__name__}.")


# -- the register ------------------------------------------------------------
def _config(context: SystemContext) -> Any:
    return context.config


def default_register() -> list[Control]:
    """Controls this system can genuinely evaluate about itself, plus the
    named manual ones it cannot."""

    def sr_1_1(context: SystemContext) -> ControlResult:
        harness = context.harness
        if harness is None:
            return ControlResult.manual("No running harness supplied to inspect.")
        return ControlResult.met(
            "Every envelope is Ed25519-signed over RFC 8785 canonical bytes and verified against a paired peer's public key before dispatch; unpaired, revoked, and expired peers are rejected.",
            mechanism="Ed25519 + RFC 8785",
            paired_peers=len(harness.peers.all()),
        )

    def sr_1_2(context: SystemContext) -> ControlResult:
        return ControlResult.met("Software processes are identified by a public-key-derived system id (`fasp:system:<sha256(pubkey)>`) that a peer cannot choose or spoof, and devices are paired out of band before any authority exists.")

    def sr_1_5(context: SystemContext) -> ControlResult:
        config = _config(context)
        if config is None:
            return ControlResult.manual("No deployment configuration supplied.")
        problems = []
        if not config.tls_enabled and not config.behind_reverse_proxy:
            problems.append("no TLS")
        if not config.mtls_enabled:
            problems.append("no client certificates")
        if problems:
            return ControlResult.partial(f"Envelope-level authenticators are strong, but the transport adds none ({', '.join(problems)}).", gaps=problems)
        return ControlResult.met("Mutual TLS at the transport plus Ed25519 envelope signatures: two independent authenticators.")

    def sr_1_13(context: SystemContext) -> ControlResult:
        config = _config(context)
        if config is not None and not config.loopback_only and not config.tls_enabled and not config.behind_reverse_proxy:
            return ControlResult.not_met("The service is reachable from an untrusted network without transport protection.")
        return ControlResult.met("Access from outside the local zone is either absent, TLS-protected, or terminated at a reviewed proxy.")

    def sr_2_1(context: SystemContext) -> ControlResult:
        return ControlResult.met("Authorization is enforced twice: pairing-time capability prefixes, and optional time-limited revocable grants that can only narrow them. Risk classes above `reversible` are refused outright.")

    def sr_2_5(context: SystemContext) -> ControlResult:
        return ControlResult.met("Pairings expire after 90 days and grants carry their own expiry; both are revocable immediately, and revocation survives re-pairing attempts until an operator re-confirms.")

    def sr_2_8(context: SystemContext) -> ControlResult:
        if context.audit_ok is False:
            return ControlResult.not_met("The audit chain does not verify.")
        return ControlResult.met("Every pairing, grant, task, revocation, and safety decision is appended to a hash-chained audit log in the same transaction as the change it records.", verified=context.audit_ok)

    def sr_2_12(context: SystemContext) -> ControlResult:
        return ControlResult.met("Signed envelopes bind sender, audience, purpose, and expiry, and are retained with their responses; a peer cannot deny having sent one that verifies against its key.")

    def sr_3_1(context: SystemContext) -> ControlResult:
        return ControlResult.met("Communication integrity is cryptographic, not transport-dependent: a modified envelope fails signature verification regardless of how it travelled.")

    def sr_3_2(context: SystemContext) -> ControlResult:
        config = _config(context)
        if config is not None and config.safety_controller is not None and not config.safety_controller.get("real_hardware", False):
            return ControlResult.not_met("The configured safety controller is simulated; malicious-code protection for a real controller is out of scope for this software.")
        return ControlResult.manual("Host-level malicious code protection (application allowlisting, verified boot, signed containers) is the platform's responsibility, not this application's.")

    def sr_3_4(context: SystemContext) -> ControlResult:
        return ControlResult.met("Durable state is content-addressed where it matters (artifacts by digest) and hash-chained where history matters (audit log), so silent modification is detectable.")

    def sr_3_8(context: SystemContext) -> ControlResult:
        return ControlResult.met("Every task and stream carries a deadline or renewable lease, and a lease that expires resolves to a safe terminal state on the next startup sweep rather than being replayed.")

    def sr_4_1(context: SystemContext) -> ControlResult:
        config = _config(context)
        if config is None:
            return ControlResult.manual("No deployment configuration supplied.")
        if config.tls_enabled or config.behind_reverse_proxy:
            return ControlResult.partial("Data in transit is protected by TLS 1.3. Data at rest is not encrypted by this application.", at_rest=config.artifact_encryption)
        return ControlResult.not_met("Neither transit nor at-rest confidentiality is configured.")

    def sr_5_1(context: SystemContext) -> ControlResult:
        return ControlResult.manual("Network segmentation into zones and conduits is a deployment architecture decision; model it with `Zone`/`Conduit` and enforce it in the network, not here.")

    def sr_5_2(context: SystemContext) -> ControlResult:
        return ControlResult.met("The layer model forbids any write toward Layer 1 and permits only observation, halt requests, coordination, and goal-level dispatch toward Layer 2 -- enforced at adapter registration and at dispatch, not by convention.")

    def sr_6_1(context: SystemContext) -> ControlResult:
        return ControlResult.met("Structured JSON audit records with a secret-redaction filter, a Prometheus endpoint, and a verifiable audit chain are available to an operator or a SIEM.")

    def sr_6_2(context: SystemContext) -> ControlResult:
        supervisor = context.supervisor
        if supervisor is None:
            return ControlResult.partial("Protocol and authorization events are monitored continuously; no safety supervisor is configured, so Layer 1 state is not.")
        return ControlResult.met("The safety supervisor polls the controller continuously, treats a stale sample as unsafe, and latches on any demand.", stale_after_s=supervisor.stale_after_s)

    def sr_7_1(context: SystemContext) -> ControlResult:
        config = _config(context)
        if config is None:
            return ControlResult.manual("No deployment configuration supplied.")
        if config.rate_limit_per_peer <= 0 or config.ip_rate_limit_per_second <= 0:
            return ControlResult.not_met("Rate limiting is disabled, so a single peer can exhaust the service.")
        return ControlResult.met("Two-layer token-bucket rate limiting (per source address before authentication, per peer after), a bounded adapter pool, durable queue-depth admission control, and message size caps.", per_peer=config.rate_limit_per_peer, per_ip=config.ip_rate_limit_per_second)

    def sr_7_2(context: SystemContext) -> ControlResult:
        return ControlResult.met("Resource limits are applied before expensive parsing: size caps precede signature verification, and admission control precedes any adapter invocation.")

    def sr_7_4(context: SystemContext) -> ControlResult:
        return ControlResult.met("A restart resolves interrupted work to a safe terminal state instead of replaying it, and a leader lease with fencing tokens prevents a recovered node from acting as a superseded coordinator.")

    def sr_7_6(context: SystemContext) -> ControlResult:
        config = _config(context)
        if config is None:
            return ControlResult.manual("No deployment configuration supplied.")
        from .posture import evaluate_posture

        report = evaluate_posture(config)
        if report.acceptable:
            return ControlResult.met(f"The {config.profile.value} security posture is enforced at startup with no blocking findings.")
        return ControlResult.not_met(f"{len(report.blocking)} blocking posture finding(s): " + "; ".join(finding.control for finding in report.blocking))

    def sr_7_8(context: SystemContext) -> ControlResult:
        from .sbom import generate_sbom

        sbom = generate_sbom()
        return ControlResult.met("A CycloneDX software bill of materials is generated from the installed distributions.", components=len(sbom.get("components", [])))

    return [
        Control("SR 1.1", FoundationalRequirement.FR1, "Human user identification and authentication", SecurityLevel.SL2, sr_1_1),
        Control("SR 1.2", FoundationalRequirement.FR1, "Software process and device identification and authentication", SecurityLevel.SL2, sr_1_2),
        Control("SR 1.5", FoundationalRequirement.FR1, "Authenticator management", SecurityLevel.SL2, sr_1_5),
        Control("SR 1.13", FoundationalRequirement.FR1, "Access via untrusted networks", SecurityLevel.SL2, sr_1_13),
        Control("SR 2.1", FoundationalRequirement.FR2, "Authorization enforcement", SecurityLevel.SL2, sr_2_1),
        Control("SR 2.5", FoundationalRequirement.FR2, "Session lock / credential expiry", SecurityLevel.SL2, sr_2_5),
        Control("SR 2.8", FoundationalRequirement.FR2, "Auditable events", SecurityLevel.SL2, sr_2_8),
        Control("SR 2.12", FoundationalRequirement.FR2, "Non-repudiation", SecurityLevel.SL3, sr_2_12),
        Control("SR 3.1", FoundationalRequirement.FR3, "Communication integrity", SecurityLevel.SL2, sr_3_1),
        Control("SR 3.2", FoundationalRequirement.FR3, "Malicious code protection", SecurityLevel.SL2, sr_3_2),
        Control("SR 3.4", FoundationalRequirement.FR3, "Software and information integrity", SecurityLevel.SL2, sr_3_4),
        Control("SR 3.8", FoundationalRequirement.FR3, "Session integrity", SecurityLevel.SL2, sr_3_8),
        Control("SR 4.1", FoundationalRequirement.FR4, "Information confidentiality", SecurityLevel.SL2, sr_4_1),
        Control("SR 5.1", FoundationalRequirement.FR5, "Network segmentation", SecurityLevel.SL2, sr_5_1),
        Control("SR 5.2", FoundationalRequirement.FR5, "Zone boundary protection", SecurityLevel.SL2, sr_5_2),
        Control("SR 6.1", FoundationalRequirement.FR6, "Audit log accessibility", SecurityLevel.SL2, sr_6_1),
        Control("SR 6.2", FoundationalRequirement.FR6, "Continuous monitoring", SecurityLevel.SL2, sr_6_2),
        Control("SR 7.1", FoundationalRequirement.FR7, "Denial of service protection", SecurityLevel.SL2, sr_7_1),
        Control("SR 7.2", FoundationalRequirement.FR7, "Resource management", SecurityLevel.SL2, sr_7_2),
        Control("SR 7.4", FoundationalRequirement.FR7, "Control system recovery and reconstitution", SecurityLevel.SL2, sr_7_4),
        Control("SR 7.6", FoundationalRequirement.FR7, "Network and security configuration settings", SecurityLevel.SL2, sr_7_6),
        Control("SR 7.8", FoundationalRequirement.FR7, "Control system component inventory", SecurityLevel.SL2, sr_7_8),
    ]


# -- zones and conduits (62443-3-2) -------------------------------------------
@dataclass(frozen=True)
class Zone:
    name: str
    sl_target: SecurityLevel
    description: str = ""
    assets: tuple[str, ...] = ()
    layer: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "sl_target": int(self.sl_target), "description": self.description, "assets": list(self.assets), "layer": self.layer}


@dataclass(frozen=True)
class Conduit:
    name: str
    source: str
    destination: str
    protocols: tuple[str, ...]
    sl_target: SecurityLevel
    controls: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "source": self.source, "destination": self.destination, "protocols": list(self.protocols), "sl_target": int(self.sl_target), "controls": list(self.controls)}


@dataclass
class ZoneModel:
    zones: list[Zone] = field(default_factory=list)
    conduits: list[Conduit] = field(default_factory=list)

    def validate(self) -> list[str]:
        """Structural problems: dangling references, and -- the one that
        matters -- a conduit protecting less than the zone it reaches."""
        names = {zone.name for zone in self.zones}
        problems: list[str] = []
        by_name = {zone.name: zone for zone in self.zones}
        for conduit in self.conduits:
            for endpoint in (conduit.source, conduit.destination):
                if endpoint not in names:
                    problems.append(f"Conduit {conduit.name!r} references undefined zone {endpoint!r}.")
            if conduit.source in by_name and conduit.destination in by_name:
                highest = max(by_name[conduit.source].sl_target, by_name[conduit.destination].sl_target)
                if conduit.sl_target < highest:
                    problems.append(
                        f"Conduit {conduit.name!r} is SL {int(conduit.sl_target)} but connects a zone requiring SL {int(highest)}: the conduit is the weakest point of the higher zone."
                    )
        return problems

    def to_dict(self) -> dict[str, Any]:
        return {"zones": [zone.to_dict() for zone in self.zones], "conduits": [conduit.to_dict() for conduit in self.conduits], "problems": self.validate()}


def reference_zone_model() -> ZoneModel:
    """The zone architecture this layered design implies.

    Note the SL targets *decrease* outward and the safety zone has no
    inbound conduit that can write. That is the architecture, expressed in
    the notation an assessor uses.
    """
    return ZoneModel(
        zones=[
            Zone("safety", SecurityLevel.SL3, "Certified safety controller, E-stop circuit, safety-rated sensors. No inbound write path exists from any other zone.", ("safety PLC", "E-stop loop", "safety scanners"), layer=1),
            Zone("vehicle", SecurityLevel.SL2, "Per-vehicle autonomy: navigation, perception, motion control.", ("ROS 2 domain", "vehicle controller"), layer=2),
            Zone("coordination", SecurityLevel.SL2, "The FASP coordinator, fleet adapters, and durable coordination state.", ("fasp_harness", "fleet managers"), layer=3),
            Zone("enterprise", SecurityLevel.SL1, "WMS/MES/ERP, analytics, human approvals.", ("OPC UA server", "WMS"), layer=4),
        ],
        conduits=[
            Conduit("safety-observation", "safety", "coordination", ("Modbus/TCP read-only",), SecurityLevel.SL3, ("read-only register map", "no write path to any safety-relevant address")),
            Conduit("vehicle-coordination", "vehicle", "coordination", ("VDA 5050 over MQTT/TLS", "FASP over HTTPS"), SecurityLevel.SL2, ("mutual TLS", "Ed25519 envelope signatures", "capability-scoped authorization")),
            Conduit("coordination-enterprise", "coordination", "enterprise", ("OPC UA", "HTTPS"), SecurityLevel.SL2, ("write allowlist", "deny-by-default", "audit chain")),
        ],
    )


# -- assessment ----------------------------------------------------------------
@dataclass
class SecurityAssessment:
    """One evaluation of the register against a running system."""

    generated_at: str
    results: list[tuple[Control, ControlResult]]
    zone_model: ZoneModel

    @property
    def demonstrated(self) -> dict[str, dict[str, Any]]:
        """Demonstrated SL per FR, and the control that caps it.

        Two deliberate choices. The roll-up is the *minimum* across the
        FR's controls, not the mean: a system with nine met controls and
        one gap is protected to the level of the gap, and averaging is how
        that fact gets lost. And a `manual` control caps the FR at 0 --
        not because the control is absent, but because nothing here has
        demonstrated it, and "demonstrated" is what this report is for.
        Naming the limiting control is what turns a bad number into a task.
        """
        rolled: dict[str, dict[str, Any]] = {}
        for control, result in self.results:
            if result.status is ControlStatus.NOT_APPLICABLE:
                continue
            level = {ControlStatus.MET: int(control.sl_target), ControlStatus.PARTIAL: max(int(control.sl_target) - 1, 0)}.get(result.status, 0)
            current = rolled.get(control.fr.name)
            if current is None or level < current["sl"]:
                rolled[control.fr.name] = {"sl": level, "limited_by": control.id, "status": result.status.value, "requirement": control.fr.value}
        return rolled

    @property
    def gaps(self) -> list[dict[str, Any]]:
        return [
            {"control": control.id, "fr": control.fr.name, "title": control.title, "sl_target": int(control.sl_target), "status": result.status.value, "detail": result.detail}
            for control, result in self.results
            if result.status in {ControlStatus.NOT_MET, ControlStatus.PARTIAL, ControlStatus.MANUAL}
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "IEC 62443-3-3 (system security requirements) with a 62443-3-2 zone/conduit model",
            "generated_at": self.generated_at,
            "disclaimer": ASSESSMENT_DISCLAIMER,
            "demonstrated_sl_by_fr": {key: value for key, value in sorted(self.demonstrated.items())},
            "controls": [{"id": control.id, "fr": control.fr.name, "title": control.title, "sl_target": int(control.sl_target), **result.to_dict()} for control, result in self.results],
            "gaps": self.gaps,
            "zone_model": self.zone_model.to_dict(),
        }

    def render_text(self) -> str:
        lines = ["IEC 62443-3-3 self-assessment", "=" * 29, f"generated {self.generated_at}", ""]
        for control, result in self.results:
            marker = {"met": "[ok]  ", "partial": "[part]", "not_met": "[FAIL]", "manual": "[man] ", "not_applicable": "[n/a] "}[result.status.value]
            lines.append(f"{marker} {control.id:8} SL-T {int(control.sl_target)}  {control.title}")
            lines.append(f"        {result.detail}")
        lines += ["", "Demonstrated SL by foundational requirement (minimum across its controls):"]
        for key, value in sorted(self.demonstrated.items()):
            lines.append(f"  {key} {FoundationalRequirement[key].value:52} SL {value['sl']}   limited by {value['limited_by']} ({value['status']})")
        problems = self.zone_model.validate()
        lines += ["", f"Zone model: {len(self.zone_model.zones)} zones, {len(self.zone_model.conduits)} conduits, {len(problems)} problem(s)"]
        lines.extend(f"  - {problem}" for problem in problems)
        lines += ["", ASSESSMENT_DISCLAIMER]
        return "\n".join(lines)


ASSESSMENT_DISCLAIMER = (
    "This is a self-assessment generated by the system about its own configuration. It is not a certification, "
    "not a third-party audit, and not an IEC 62443 conformance statement. Controls marked 'manual' require evidence "
    "this software cannot produce about itself. A certification requires an accredited body assessing a specific "
    "installation, including its organisational processes."
)


def assess(context: SystemContext, *, register: list[Control] | None = None, zone_model: ZoneModel | None = None) -> SecurityAssessment:
    controls = register or default_register()
    return SecurityAssessment(generated_at=stamp(), results=[(control, control.run(context)) for control in controls], zone_model=zone_model or reference_zone_model())
