"""`python -m fasp_harness <command>`: the operator-facing surface.

Each command answers a question someone actually asks during a deployment,
and each is designed to be usable in a pipeline -- non-zero exit on a
failing verdict, `--json` for machine consumption.

    serve            run a node
    discover         scan a CIDR for FASP id cards
    rt-probe         what timing can this host honestly offer?
    safety-case      run the safety argument's evidence; fail on a gap
    security-report  IEC 62443 self-assessment and posture verdict
    posture          just the startup gate, as a check
    sbom             CycloneDX bill of materials
    hil              run the hardware-in-the-loop safety scenarios
    layers           print the layer model this build enforces
    guard-budget     what separation and resync rate does this link need?
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .protocol.errors import FaspError


def _emit(payload: Any, text: str, as_json: bool) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str) if as_json else text)


def command_rt_probe(args: argparse.Namespace) -> int:
    from .realtime.capability import probe_realtime_capability

    capability = probe_realtime_capability(measure=not args.no_measure)
    _emit(capability.to_dict(), json.dumps(capability.to_dict(), indent=2, sort_keys=True, default=list) + f"\n\n{capability.summary()}", args.json)
    return 0


def command_layers(args: argparse.Namespace) -> int:
    from .layers import PERMITTED_INTERACTIONS, RESERVED_L1_FUNCTIONS, Layer, describe_layers

    lines = ["Layer model enforced by this build", "=" * 33, ""]
    for layer in Layer:
        permitted = ", ".join(sorted(item.name.lower() for item in PERMITTED_INTERACTIONS[layer]))
        lines.append(f"Layer {layer.value}  {layer.title}")
        lines.append(f"          FASP may: {permitted}")
    lines += ["", f"Reserved Layer 1 function patterns ({len(RESERVED_L1_FUNCTIONS)}), refused at every layer and risk class:"]
    lines.extend(f"  - {pattern}\n      {reason}" for pattern, reason in RESERVED_L1_FUNCTIONS)
    _emit({"layers": describe_layers(), "reserved": [{"pattern": pattern, "reason": reason} for pattern, reason in RESERVED_L1_FUNCTIONS]}, "\n".join(lines), args.json)
    return 0


def _load_node(args: argparse.Namespace) -> Any:
    from .deployment import NodeConfig, build_node

    config = NodeConfig.from_file(Path(args.config)) if getattr(args, "config", None) else NodeConfig()
    return build_node(config, enforce_posture=False)


def command_safety_case(args: argparse.Namespace) -> int:
    from .safety.reference_case import build_reference_case
    from .security.posture import DeploymentConfig

    node = _load_node(args) if getattr(args, "config", None) else None
    deployment = DeploymentConfig(profile=node.config.profile, state_dir=node.config.state_dir) if node else None
    case = build_reference_case(
        harness=node.harness if node else None,
        config=deployment,
        supervisor=node.supervisor if node else None,
    )
    report = case.verify()
    _emit(report.to_dict(), report.render_text(), args.json)
    if node is not None:
        node.stop()
    # Non-zero when a claim that should be supported is not. Delegated and
    # undeveloped claims do NOT fail the run: they are declared gaps, and
    # failing on them would push someone to delete the honest declaration.
    return 1 if report.failures else 0


def command_security_report(args: argparse.Namespace) -> int:
    from .security.iec62443 import SystemContext, assess
    from .security.posture import DeploymentConfig

    node = _load_node(args) if getattr(args, "config", None) else None
    deployment = DeploymentConfig(
        profile=node.config.profile if node else __import__("fasp_harness.security.posture", fromlist=["SecurityProfile"]).SecurityProfile.DEVELOPMENT,
        state_dir=node.config.state_dir if node else Path(".fasp"),
        safety_controller=node.supervisor.driver.describe() if node and node.supervisor and node.supervisor.driver else None,
    )
    assessment = assess(
        SystemContext(
            config=deployment,
            harness=node.harness if node else None,
            supervisor=node.supervisor if node else None,
            audit_ok=node.harness.audit.verify()[0] if node else None,
        )
    )
    _emit(assessment.to_dict(), assessment.render_text(), args.json)
    if node is not None:
        node.stop()
    return 1 if any(gap["status"] == "not_met" for gap in assessment.gaps) else 0


def command_posture(args: argparse.Namespace) -> int:
    from .security.posture import DeploymentConfig, SecurityProfile, evaluate_posture

    node = _load_node(args) if getattr(args, "config", None) else None
    config = DeploymentConfig(
        profile=SecurityProfile(args.profile) if args.profile else (node.config.profile if node else SecurityProfile.DEVELOPMENT),
        state_dir=node.config.state_dir if node else Path(args.state_dir),
        host=args.host,
        tls_cert=Path(args.tls_cert) if args.tls_cert else None,
        tls_key=Path(args.tls_key) if args.tls_key else None,
        tls_client_ca=Path(args.tls_client_ca) if args.tls_client_ca else None,
        safety_controller=node.supervisor.driver.describe() if node and node.supervisor and node.supervisor.driver else None,
    )
    report = evaluate_posture(config)
    _emit(report.to_dict(), report.render_text(), args.json)
    if node is not None:
        node.stop()
    return 0 if report.acceptable else 1


def command_sbom(args: argparse.Namespace) -> int:
    from .security.sbom import generate_sbom, render

    document = generate_sbom()
    print(render(document))
    return 0


def command_hil(args: argparse.Namespace) -> int:
    from .hil.bench import HilBench, SimulatedSafetyDut
    from .hil.scenario import standard_safety_scenarios

    scenarios = [scenario for scenario in standard_safety_scenarios() if not args.scenario or scenario.name == args.scenario]
    if not scenarios:
        print(f"No scenario named {args.scenario!r}. Available: {[item.name for item in standard_safety_scenarios()]}", file=sys.stderr)
        return 2
    device = SimulatedSafetyDut(stale_after_s=0.3)
    bench = HilBench(device, poll_interval_ms=args.poll_interval_ms)
    reports = []
    for scenario in scenarios:
        device.reset()
        reports.append(bench.run(scenario))
    if args.json:
        print(json.dumps([report.to_dict() for report in reports], indent=2, sort_keys=True))
    else:
        for report in reports:
            print(report.render_text())
            print()
        print("NOTE: this ran against a simulated device. A timing claim about a machine requires these scenarios on that machine's hardware.")
    return 0 if all(report.passed for report in reports) else 1


def command_zones(args: argparse.Namespace) -> int:
    from .security.iec62443 import reference_zone_model

    model = reference_zone_model()
    problems = model.validate()
    lines = ["IEC 62443-3-2 zones and conduits", "=" * 32, ""]
    for zone in model.zones:
        lines.append(f"zone {zone.name:14} SL-T {int(zone.sl_target)}  (layer {zone.layer})  {zone.description}")
    lines.append("")
    for conduit in model.conduits:
        lines.append(f"conduit {conduit.name:22} {conduit.source} -> {conduit.destination}  SL-T {int(conduit.sl_target)}")
        lines.append(f"         protocols: {', '.join(conduit.protocols)}")
        lines.append(f"         controls:  {', '.join(conduit.controls)}")
    lines += ["", f"{len(problems)} problem(s)"] + [f"  - {problem}" for problem in problems]
    _emit(model.to_dict(), "\n".join(lines), args.json)
    return 1 if problems else 0


def command_guard_budget(args: argparse.Namespace) -> int:
    """What separation does this link and platform actually require?

    The question an integrator asks once the radio is chosen and before
    the aisle width is fixed. Everything here is arithmetic over numbers
    they already have -- a measured round trip, a speed limit, a crystal
    tolerance -- and the point is to make the trade visible: a slower
    radio is a wider guard band is a wider aisle, and that chain is
    usually invisible until the shelving is already bolted down.

    Feed it the p99 round trip, not the mean. Queueing on a shared radio
    is heavy-tailed, and the mean describes a link nobody experiences.
    """
    from .spatial.clock import ClockEstimate, TimeInterval
    from .spatial.guard import GuardPolicy, Morphology, envelope_for
    from .spatial.linalg import identity, mat_scale
    from .spatial.state import Aerial, ConstantVelocity, GroundVehicle, StateReport

    policy = GuardPolicy(
        risk_alpha=args.risk,
        dimensions=args.dimensions,
        latency_margin_s=args.round_trip_ms / 1000.0 / 2.0,
        control_period_s=args.control_period_ms / 1000.0,
    )
    morphology = Morphology(args.morphology)
    motion = {"air": Aerial(), "ground": GroundVehicle()}.get(args.morphology, ConstantVelocity())

    # The clock bound this link can hold, from the round trip alone.
    estimate = ClockEstimate(
        offset_ms=0.0,
        skew_ppm=0.0,
        skew_uncertainty_ppm=args.clock_ppm,
        skew_measured=False,
        base_uncertainty_ms=args.round_trip_ms / 2.0,
        reference_local_ms=0.0,
        best_round_trip_ms=args.round_trip_ms,
        samples=0,
    )
    resync_s = estimate.resync_interval_s(args.clock_tolerance_ms)

    covariance = mat_scale(identity(6), args.position_sigma_m**2)
    for axis in range(3, 6):
        covariance[axis][axis] = max(args.position_sigma_m**2, 1e-6)
    report = StateReport(
        robot_id="subject",
        frame_id="site",
        position_m=[0.0, 0.0, 0.0],
        velocity_mps=[args.speed_limit_mps, 0.0, 0.0],
        covariance=covariance,
        stamp=TimeInterval(0.0, estimate.base_uncertainty_ms),
        motion=motion,
        speed_limit_mps=args.speed_limit_mps,
    )

    rows = []
    for age_ms in (0.0, 250.0, 500.0, 1_000.0, 2_000.0, 5_000.0):
        envelope = envelope_for(report, policy, age_ms, morphology=morphology, body_radius_m=args.body_radius_m)
        rows.append(
            {
                "age_ms": age_ms,
                "radius_m": envelope.radius_m,
                "basis": envelope.basis,
                "beyond_model": envelope.beyond_model,
                "fits_clearance": None if args.clearance_m is None else envelope.radius_m <= args.clearance_m,
            }
        )

    payload = {
        "policy": policy.to_dict(),
        "link": {"round_trip_ms": args.round_trip_ms, "clock_ppm": args.clock_ppm, "clock_bound_ms": estimate.base_uncertainty_ms},
        "platform": {"morphology": args.morphology, "speed_limit_mps": args.speed_limit_mps, "body_radius_m": args.body_radius_m},
        "resync_interval_s": resync_s,
        "clock_tolerance_ms": args.clock_tolerance_ms,
        "bands": rows,
    }

    lines = [
        f"Guard budget for a {args.morphology} platform on a {args.round_trip_ms:g} ms link",
        "=" * 62,
        "",
        f"  residual risk        {policy.risk_alpha:g} over {policy.dimensions} dimensions -> k = {policy.coverage_k:.4f}",
        f"  clock bound          {estimate.base_uncertainty_ms:.1f} ms (half the round trip)",
        f"  decision margin      {policy.decision_margin_s * 1000.0:.0f} ms still ahead when the band is sized",
    ]
    if resync_s > 0.0:
        lines.append(f"  resync every         {resync_s:.1f} s to hold {args.clock_tolerance_ms:g} ms at {args.clock_ppm:g} ppm")
    else:
        lines.append(f"  resync               cannot hold {args.clock_tolerance_ms:g} ms: the link's own bound already exceeds it")
    lines += ["", "  message age    guard radius    sized by", "  " + "-" * 44]
    for row in rows:
        flag = ""
        if row["fits_clearance"] is False:
            flag = "  EXCEEDS CLEARANCE"
        elif row["beyond_model"]:
            flag = "  (past model horizon)"
        lines.append(f"  {row['age_ms']:>8.0f} ms    {row['radius_m']:>8.3f} m    {row['basis']:<12}{flag}")

    failed = args.clearance_m is not None and any(row["fits_clearance"] is False for row in rows)
    if args.clearance_m is not None:
        lines += ["", f"  available clearance  {args.clearance_m:g} m"]
        lines.append("  verdict              " + ("a band exceeds the clearance before 5 s of silence" if failed else "every band fits within 5 s of silence"))
    _emit(payload, "\n".join(lines), args.json)
    return 1 if failed else 0


def _morphology_choices() -> list[str]:
    from .spatial.guard import Morphology

    return [item.value for item in Morphology]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m fasp_harness", description="FASP harness: layered coordination for autonomous systems.")
    subparsers = parser.add_subparsers(dest="command")

    def add(name: str, help_text: str, handler: Any) -> argparse.ArgumentParser:
        subparser = subparsers.add_parser(name, help=help_text)
        subparser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
        subparser.set_defaults(handler=handler)
        return subparser

    probe = add("rt-probe", "Report this host's honest real-time capability.", command_rt_probe)
    probe.add_argument("--no-measure", action="store_true", help="Skip the sleep-jitter measurement.")

    add("layers", "Print the layer model and the reserved Layer 1 functions.", command_layers)

    case = add("safety-case", "Run the safety case's evidence and report which claims hold.", command_safety_case)
    case.add_argument("--config", help="Node configuration JSON, so the evidence runs against a real deployment.")

    report = add("security-report", "IEC 62443-3-3 self-assessment against the running configuration.", command_security_report)
    report.add_argument("--config", help="Node configuration JSON.")

    posture = add("posture", "Evaluate the startup security gate for a configuration.", command_posture)
    posture.add_argument("--config", help="Node configuration JSON.")
    posture.add_argument("--profile", choices=["development", "hardened", "production"])
    posture.add_argument("--host", default="127.0.0.1")
    posture.add_argument("--state-dir", default=".fasp")
    posture.add_argument("--tls-cert")
    posture.add_argument("--tls-key")
    posture.add_argument("--tls-client-ca")

    add("sbom", "Emit a CycloneDX software bill of materials.", command_sbom)

    hil = add("hil", "Run the hardware-in-the-loop safety scenarios.", command_hil)
    hil.add_argument("--scenario", help="Run one scenario by name.")
    hil.add_argument("--poll-interval-ms", type=float, default=1.0)

    add("zones", "Print the IEC 62443-3-2 zone and conduit model.", command_zones)

    budget = add("guard-budget", "Separation and resync rate required by a given link and platform.", command_guard_budget)
    budget.add_argument("--round-trip-ms", type=float, default=40.0, help="Measured p99 round trip, not the mean.")
    budget.add_argument("--speed-limit-mps", type=float, default=2.0, help="What the platform could do, not what it was doing.")
    budget.add_argument("--morphology", choices=_morphology_choices(), default="ground")
    budget.add_argument("--risk", type=float, default=1e-6, help="Residual risk the guard band is sized for.")
    budget.add_argument("--dimensions", type=int, choices=[1, 2, 3], default=3)
    budget.add_argument("--clock-ppm", type=float, default=50.0, help="Crystal tolerance; 50 ppm is a commodity part.")
    budget.add_argument("--clock-tolerance-ms", type=float, default=1.0, help="Clock agreement the deployment needs to hold.")
    budget.add_argument("--position-sigma-m", type=float, default=0.1, help="Onboard localisation sigma.")
    budget.add_argument("--body-radius-m", type=float, default=0.45)
    budget.add_argument("--control-period-ms", type=float, default=100.0)
    budget.add_argument("--clearance-m", type=float, help="Available clearance; exit non-zero if a band exceeds it.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2
    try:
        return int(args.handler(args))
    except FaspError as error:
        print(f"{error.code}: {error.detail}", file=sys.stderr)
        return 2
