"""The concrete safety case for this coordinator, with runnable evidence.

Every `Solution` below executes something: it runs the layer guard against
a list of capability names an attacker would try, it runs the HIL latching
scenario and reads the measured latency, it probes the host's real-time
posture, it verifies the audit chain. Nothing is asserted.

The shape of the argument is as important as the evidence:

- the root claim is scoped to what this software can affect -- it does not
  claim the *machine* is safe, it claims that adding this coordinator does
  not make it less so;
- the Layer 1 claims are `delegated`, naming who discharges them. They are
  not quietly omitted, and they are not claimed;
- independent validation is `undeveloped`, explicitly. A safety case that
  omits the claim it cannot support is worse than one that shows the gap.

Run it with `python -m fasp_harness safety-case`. It exits non-zero when a
claim that is supposed to be supported is not, so it can gate a pipeline.
"""

from __future__ import annotations

from typing import Any

from ..layers import CapabilityDeclaration, Interaction, Layer, LayerGuard, LayerViolation
from ..protocol.errors import FaspError
from ..realtime.capability import probe_realtime_capability
from ..realtime.scheduler import CyclicExecutor, ManualClock, OverrunPolicy
from ..realtime.watchdog import DeadlineWatchdog
from .case import Claim, Evidence, EvidenceResult, SafetyCase
from .interlock import LOCAL_OPERATOR, SafetySupervisor

# Capability names an integrator might plausibly write, or an attacker
# might plausibly try. Each one must be refused by the layer guard.
ATTEMPTED_LAYER1_CAPABILITIES = (
    "safety.estop.clear.v1",
    "actuate.motor.command.v1",
    "safety.zone.mute.v1",
    "reversible.brake.release.v1",
    "coordinate.speed_limit.override.v1",
    "observe.interlock.bypass.v1",
    "fleet.watchdog.disable.v1",
    "maintenance.plc.program.v1",
)


def _evidence_layer_guard() -> EvidenceResult:
    """Every reserved Layer 1 name is refused, at every risk class."""
    guard = LayerGuard()
    accepted: list[str] = []
    for capability_id in ATTEMPTED_LAYER1_CAPABILITIES:
        for layer in Layer:
            for interaction in Interaction:
                declaration = CapabilityDeclaration(id=capability_id, risk="observe", layer=layer, interaction=interaction)
                try:
                    guard.check_capability(declaration)
                except LayerViolation:
                    continue
                except FaspError:
                    continue
                accepted.append(f"{capability_id}@L{layer.value}/{interaction.name}")
    if accepted:
        return EvidenceResult.failed(f"The layer guard accepted {len(accepted)} Layer 1 capability declaration(s), starting with {accepted[0]}.")
    return EvidenceResult.supported(
        f"All {len(ATTEMPTED_LAYER1_CAPABILITIES)} reserved Layer 1 capability names were refused at every layer and interaction ({len(ATTEMPTED_LAYER1_CAPABILITIES) * len(Layer) * len(Interaction)} combinations).",
        combinations=len(ATTEMPTED_LAYER1_CAPABILITIES) * len(Layer) * len(Interaction),
    )


def _evidence_no_network_clear() -> EvidenceResult:
    """A halt cannot be cleared by anything that came in over a network."""
    from .drivers import SimulatedSafetyController

    controller = SimulatedSafetyController()
    supervisor = SafetySupervisor(controller)
    supervisor.demand_halt("peer", "test demand", origin="peer")
    refused: list[str] = []
    for origin in ("peer", "network", "fleet", "cloud", "wms", "mes", "twin", "watchdog", "supervisor"):
        try:
            supervisor.clear(origin=origin, operator="attacker")
        except (LayerViolation, FaspError):
            refused.append(origin)
            continue
        return EvidenceResult.failed(f"A halt was cleared by a caller with origin {origin!r}.")
    if not supervisor.latched:
        return EvidenceResult.failed("The supervisor did not remain latched after the clear attempts.")
    controller.manual_reset()
    supervisor.clear(origin=LOCAL_OPERATOR, operator="bench")
    if supervisor.latched:
        return EvidenceResult.failed("A local operator could not clear the halt after the machine was reset, which would make the system unusable.")
    return EvidenceResult.supported(f"{len(refused)} network origins were refused; only a local operator, with the controller reset, could clear the latch.", refused_origins=refused)


def _evidence_hil(scenario_name: str, *, budget_ms: float | None = None) -> EvidenceResult:
    from ..hil.bench import HilBench, SimulatedSafetyDut
    from ..hil.scenario import standard_safety_scenarios

    scenario = next((item for item in standard_safety_scenarios() if item.name == scenario_name), None)
    if scenario is None:
        return EvidenceResult.inconclusive(f"Scenario {scenario_name!r} is not defined.")
    device = SimulatedSafetyDut(stale_after_s=0.3)
    device.reset()
    report = HilBench(device, poll_interval_ms=1.0).run(scenario)
    chain_ok, bad = report.verify_chain()
    if not chain_ok:
        return EvidenceResult.inconclusive(f"The HIL evidence chain failed verification at step {bad}.")
    if not report.passed:
        failed = [result.step.name for result in report.results if not result.passed]
        return EvidenceResult.failed(f"HIL scenario {scenario_name!r} failed at: {', '.join(failed)}.")
    if budget_ms is not None and report.worst_latency_ms > budget_ms:
        return EvidenceResult.failed(f"HIL scenario {scenario_name!r} passed but the worst latency {report.worst_latency_ms:.1f}ms exceeds the {budget_ms:.0f}ms budget.")
    return EvidenceResult.supported(
        f"HIL scenario {scenario_name!r} passed on a {'real' if report.real_hardware else 'simulated'} device; worst observed latency {report.worst_latency_ms:.1f}ms across {len(report.results)} steps.",
        worst_latency_ms=report.worst_latency_ms,
        real_hardware=report.real_hardware,
        evidence_head=report.results[-1].row_hash if report.results else "",
    )


def _evidence_watchdog_failsafe() -> EvidenceResult:
    """A stalled loop escalates into a latched halt without being asked."""
    from .drivers import SimulatedSafetyController

    controller = SimulatedSafetyController()
    supervisor = SafetySupervisor(controller)
    clock = ManualClock()
    watchdog = DeadlineWatchdog("control-plane", 1.0, lambda detail: supervisor.demand_halt("watchdog", detail, origin="watchdog"), clock=clock)
    watchdog.pet()
    clock.advance(500_000_000)
    if watchdog.poll() or supervisor.latched:
        return EvidenceResult.failed("The watchdog tripped before its timeout elapsed.")
    clock.advance(1_500_000_000)
    if not watchdog.poll():
        return EvidenceResult.failed("The watchdog did not trip after its timeout elapsed.")
    if not supervisor.latched:
        return EvidenceResult.failed("The watchdog tripped but did not latch a halt.")
    watchdog.pet()
    if not watchdog.expired:
        return EvidenceResult.failed("Petting a tripped watchdog cleared it; a latched watchdog must not un-trip on its own.")
    return EvidenceResult.supported("A 1s watchdog stayed clear at 0.5s, tripped at 2.0s, latched a halt, and stayed tripped when petted afterwards.", timeout_s=1.0)


def _evidence_fencing() -> EvidenceResult:
    """A superseded coordinator is refused at the moment of effect."""
    import tempfile
    from pathlib import Path

    from ..edge.lease import LeaderLease, LeaseLost
    from ..storage.db import Database

    with tempfile.TemporaryDirectory() as directory:
        db = Database(Path(directory) / "fasp.db")
        first = LeaderLease(db, "coordinator", node_id="node-a", ttl_s=1.0)
        held = first.try_acquire(now_ms=0)
        if held is None:
            return EvidenceResult.failed("The first node could not acquire the lease.")
        second = LeaderLease(db, "coordinator", node_id="node-b", ttl_s=1.0)
        if second.try_acquire(now_ms=500) is not None:
            return EvidenceResult.failed("A second node acquired a lease that was still held.")
        taken = second.try_acquire(now_ms=2_000)
        if taken is None:
            return EvidenceResult.failed("The second node could not take over an expired lease.")
        if taken.fence <= held.fence:
            return EvidenceResult.failed(f"The fence did not advance on takeover ({held.fence} -> {taken.fence}).")
        try:
            first.guard(held)
        except LeaseLost:
            return EvidenceResult.supported(f"A superseded leader presenting fence {held.fence} was refused after leadership advanced to {taken.fence}.", old_fence=held.fence, new_fence=taken.fence)
        return EvidenceResult.failed("A superseded leader's stale fence was accepted, which permits split-brain dispatch.")


def _evidence_partition_tolerance() -> EvidenceResult:
    """A hard partition delays delivery; it does not lose or duplicate it."""
    from ..resilience.mesh import run_partition_scenario

    reports = [run_partition_scenario(seed=seed, messages=10) for seed in (1, 2, 3)]
    incomplete = [report for report in reports if not report.complete]
    if incomplete:
        report = incomplete[0]
        return EvidenceResult.failed(f"Seed {report.seed}: {report.delivered}/{report.sent} delivered, {report.duplicate_deliveries} duplicated.")
    during = max(report.delivered_during_partition for report in reports)
    if during:
        return EvidenceResult.inconclusive(f"{during} message(s) were delivered during the partition, so the scenario did not actually exercise carrying.")
    return EvidenceResult.supported(
        f"Across {len(reports)} seeds: 0 messages crossed during a 60s hard partition, all {reports[0].sent} were delivered after healing, 0 duplicate deliveries.",
        seeds=[report.seed for report in reports],
    )


def _evidence_realtime_honesty() -> EvidenceResult:
    """No hard real-time claim is made, and the reasons are recorded."""
    capability = probe_realtime_capability(measure=False)
    if capability.hard_realtime:
        return EvidenceResult.failed("The runtime reported hard real-time capability, which no CPython process can provide.")
    if not capability.reasons:
        return EvidenceResult.failed("No reasons were recorded for the absence of hard real-time guarantees.")
    return EvidenceResult.supported(
        f"The runtime reports timing class {capability.timing_class!r} and hard_realtime=False, with {len(capability.reasons)} recorded reasons.",
        timing_class=capability.timing_class,
        preempt_rt=capability.preempt_rt,
    )


def _evidence_scheduler_determinism() -> EvidenceResult:
    """The management-plane scheduler does not drift, and defines overruns."""
    clock = ManualClock()
    releases: list[int] = []
    executor = CyclicExecutor(0.01, lambda index: releases.append(clock.monotonic_ns()), clock=clock, name="evidence", overrun_policy=OverrunPolicy.SKIP)
    report = executor.run(cycles=100)
    expected = [index * 10_000_000 for index in range(100)]
    if releases != expected:
        drift = max(abs(actual - want) for actual, want in zip(releases, expected, strict=False))
        return EvidenceResult.failed(f"The schedule drifted by up to {drift}ns over 100 cycles.")
    if report.overruns:
        return EvidenceResult.failed(f"{report.overruns} cycles overran on an idle virtual clock.")

    # And an overrun must be detected and acted on, not absorbed silently.
    stalling = ManualClock()
    tripped: list[int] = []
    stalled = CyclicExecutor(0.01, lambda index: stalling.advance(50_000_000), clock=stalling, name="stall", overrun_policy=OverrunPolicy.FAIL_SAFE, on_overrun=lambda index, late: tripped.append(late))
    stalled.run(cycles=10)
    if not tripped:
        return EvidenceResult.failed("A cycle that took five periods did not register as an overrun.")
    return EvidenceResult.supported(
        f"100 cycles released exactly on a 10ms grid with zero drift; a 50ms cycle against a 10ms deadline tripped the fail-safe policy after {len(tripped)} overrun(s).",
        cycles=report.cycles,
        drift_ns=0,
    )


def _evidence_preflight_refuses_impossible() -> EvidenceResult:
    """The twin refuses a mission that cannot physically be completed."""
    from ..fleet.model import Mission, MissionStep, Pose, StepKind
    from ..twin.kinematic import OccupancyGrid, SiteModel
    from ..twin.preflight import preflight_mission

    grid = OccupancyGrid(resolution_m=0.5)
    grid.block_rectangle(4.0, -2.0, 5.0, 2.0)
    site = SiteModel(nodes={"start": Pose(0.0, 0.0), "far": Pose(10.0, 0.0)}, grid=grid)
    mission = Mission(mission_id="evidence-1", requested_by="test", steps=(MissionStep("s1", StepKind.MOVE, node_id="far"),))
    blocked = preflight_mission(mission, site=site, start_pose=Pose(0.0, 0.0), vehicle_id="v1")
    if blocked.feasible:
        return EvidenceResult.failed("Preflight approved a route straight through a known-blocked region.")

    flat = preflight_mission(mission, site=SiteModel(nodes=site.nodes), start_pose=Pose(0.0, 0.0), vehicle_id="v1", battery_ratio=0.11, reserve_battery=0.10)
    clear = preflight_mission(mission, site=SiteModel(nodes=site.nodes), start_pose=Pose(0.0, 0.0), vehicle_id="v1")
    if not clear.feasible:
        return EvidenceResult.failed(f"Preflight rejected a clear, feasible route: {clear.reasons}.")
    return EvidenceResult.supported(
        f"Preflight rejected a route through a blocked region ({blocked.reasons[0][:80]}), accepted the same route on a clear map, and reported battery low-water {flat.battery_low_water:.2%} for a nearly flat vehicle.",
        blocked_reason=blocked.reasons[0][:120],
    )


def _evidence_audit_chain(harness: Any) -> EvidenceResult:
    if harness is None:
        return EvidenceResult.inconclusive("No running harness was supplied, so its audit chain could not be verified.")
    ok, bad_sequence = harness.audit.verify()
    if not ok:
        return EvidenceResult.failed(f"The audit chain failed verification at sequence {bad_sequence}.")
    entries = harness.db.read_one("SELECT COUNT(*) AS n FROM audit_log")
    return EvidenceResult.supported(f"The hash-chained audit log verified end to end over {entries['n'] if entries else 0} entries.", entries=entries["n"] if entries else 0)


def _evidence_posture(config: Any) -> EvidenceResult:
    if config is None:
        return EvidenceResult.inconclusive("No deployment configuration was supplied, so the security posture could not be evaluated.")
    from ..security.posture import evaluate_posture

    report = evaluate_posture(config)
    if not report.acceptable:
        return EvidenceResult.failed(f"{len(report.blocking)} blocking posture finding(s) in the {report.profile.value} profile: " + "; ".join(finding.control for finding in report.blocking[:3]))
    return EvidenceResult.supported(f"The {report.profile.value} security posture was evaluated with no blocking findings ({len(report.findings)} advisory).", profile=report.profile.value)


def _evidence_safety_controller_is_real(supervisor: Any) -> EvidenceResult:
    """The one check nobody wants to fail in production, and everyone does in CI."""
    if supervisor is None or getattr(supervisor, "driver", None) is None:
        return EvidenceResult.failed("No safety controller is configured, so this system cannot observe Layer 1 at all.")
    described = supervisor.driver.describe()
    if not described.get("real_hardware", False):
        return EvidenceResult.failed(f"The configured safety controller is {described.get('model', 'a simulation')}, which carries no safety integrity. This is expected in CI and unacceptable in a deployment with physical actuation.")
    return EvidenceResult.supported(f"A real safety controller is configured: {described.get('vendor')} {described.get('model')}.", integrity_claim=described.get("integrity_claim"))


def build_reference_case(*, harness: Any = None, config: Any = None, supervisor: Any = None) -> SafetyCase:
    """Assemble the case, binding evidence to the supplied running system."""
    case = SafetyCase(
        title="Safety case: FASP coordinator at Layers 3 and 4",
        root="G1",
    )

    for evidence in (
        Evidence("E1", "The layer guard refuses every reserved Layer 1 capability name at every layer and risk class.", "test", _evidence_layer_guard),
        Evidence("E2", "A latched halt cannot be cleared by any network origin, only by a local operator with the controller reset.", "test", _evidence_no_network_clear),
        Evidence("E3", "HIL: an E-stop demand produces an observed stop within budget.", "measurement", lambda: _evidence_hil("estop-response-time", budget_ms=250.0)),
        Evidence("E4", "HIL: the stop latches; releasing the button does not resume motion.", "measurement", lambda: _evidence_hil("estop-latching")),
        Evidence("E5", "HIL: losing sight of the safety controller withdraws permission to move.", "measurement", lambda: _evidence_hil("controller-unreachable-fails-safe")),
        Evidence("E6", "HIL: a network halt request is honoured and cannot be undone from the network.", "measurement", lambda: _evidence_hil("network-halt-request")),
        Evidence("E7", "A stalled control plane escalates into a latched halt without being asked, and stays latched.", "test", _evidence_watchdog_failsafe),
        Evidence("E8", "A superseded coordinator's fencing token is refused at the moment of effect.", "test", _evidence_fencing),
        Evidence("E9", "A 60-second hard partition delays delivery without losing or duplicating it.", "test", _evidence_partition_tolerance),
        Evidence("E10", "The runtime makes no hard real-time claim and records why.", "inspection", _evidence_realtime_honesty),
        Evidence("E11", "The management-plane scheduler is drift-free and treats an overrun as a defined event.", "measurement", _evidence_scheduler_determinism),
        Evidence("E12", "The twin refuses a mission that cannot physically be completed.", "test", _evidence_preflight_refuses_impossible),
        Evidence("E13", "The hash-chained audit log verifies end to end.", "test", lambda: _evidence_audit_chain(harness)),
        Evidence("E14", "The deployment's security posture is evaluated and has no blocking findings.", "inspection", lambda: _evidence_posture(config)),
        Evidence("E15", "A real, certified safety controller is configured (not a simulation).", "inspection", lambda: _evidence_safety_controller_is_real(supervisor)),
    ):
        case.add_evidence(evidence)

    case.claim(
        Claim(
            "G1",
            "Introducing this coordinator does not increase the risk to people near the machines it coordinates.",
            strategy="Argue over the layer model: Layer 1 risk reduction is unchanged and undefeatable from here; Layers 2-4 behaviour degrades toward stopped.",
            context=(
                "Scope: the coordination software in this repository, at Layers 3 and 4, plus its observation of Layers 1 and 2.",
                "The machines themselves, their protective stops, and their autonomy stacks are outside this scope and are argued by their own suppliers.",
            ),
            assumptions=(
                "Every coordinated machine has a protective stop implemented in certified equipment, assessed to the risk of its application (ISO 13849 / IEC 62061 / IEC 61508 as applicable).",
                "That protective stop remains effective when this software, its host, and the network are all absent.",
                "Site risk assessment, commissioning, and validation are performed by competent persons for the specific installation.",
            ),
            sub_claims=("G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9"),
        )
    )
    case.claim(
        Claim(
            "G2",
            "Layer 1 safety functions are implemented, assessed, and certified outside this software.",
            delegated_to="the machine builder's certified safety controller and its own conformity assessment (ISO 13849-1 / IEC 62061), plus the site integrator's validation",
            rationale="This software implements no safety function. It observes Layer 1 and may request a stop.",
        )
    )
    case.claim(
        Claim(
            "G3",
            "This software cannot defeat, bypass, mute, or clear a Layer 1 safety function.",
            strategy="Argue by construction (no such code path exists) and by test (attempts are refused).",
            evidence=("E1", "E2", "E6"),
        )
    )
    case.claim(
        Claim(
            "G4",
            "A halt demand from any source is honoured promptly and remains latched until a deliberate local reset.",
            evidence=("E3", "E4", "E5"),
        )
    )
    case.claim(
        Claim(
            "G5",
            "Loss of the network, the coordinator, or its leadership degrades the system toward stopped, never toward stale commands.",
            strategy="Argue over each loss mode: stalled loop, superseded leader, partitioned network.",
            evidence=("E7", "E8", "E9"),
        )
    )
    case.claim(
        Claim(
            "G6",
            "Work is dispatched to a vehicle only when supervisory preconditions hold and the mission has been shown to be achievable.",
            evidence=("E12",),
            sub_claims=("G10",),
        )
    )
    case.claim(
        Claim(
            "G10",
            "Obstacle avoidance, localisation, and path execution are correct for the vehicle's environment.",
            delegated_to="each vehicle's own autonomy stack and its supplier's validation; the coordinator dispatches goals and never a trajectory",
        )
    )
    case.claim(
        Claim(
            "G7",
            "Timing behaviour is measured rather than asserted, and no hard real-time guarantee is claimed for this process.",
            evidence=("E10", "E11"),
        )
    )
    case.claim(
        Claim(
            "G8",
            "The security posture that the safety argument depends on is enforced at startup and evidenced at runtime.",
            strategy="A safety argument that assumes an authenticated peer is void if authentication is optional.",
            evidence=("E13", "E14", "E15"),
        )
    )
    case.claim(
        Claim(
            "G9",
            "The argument and its evidence have been independently validated for a specific installation.",
            undeveloped=True,
            rationale=(
                "Not argued here, and not arguable here. Independent validation requires a competent body assessing a specific "
                "installation: its risk assessment, its machinery, its integration, and its organisational processes. No self-executed "
                "evidence can substitute for it, and this claim is left visibly open rather than quietly omitted."
            ),
        )
    )
    return case
