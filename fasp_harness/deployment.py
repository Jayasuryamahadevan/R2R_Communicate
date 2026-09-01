"""Assemble a complete industrial node from configuration, in one place.

Every part of this repository is usable on its own, which is right for a
library and unhelpful for an operator. This module is the other half: one
function that takes a description of a deployment and returns a wired node
-- safety supervisor observing a real controller, fleet adapters for
whichever vendors are present, a leader lease if this is a standby pair, a
twin if a site map is configured, an outbox, health probes, and the
periodic loops that keep them all current.

Two ordering decisions here are load bearing:

- the security posture is evaluated and enforced *before* anything binds a
  socket or connects to a controller. A deployment that would be refused is
  refused before it can do anything;
- the safety supervisor is created and polled *before* the first mission
  can be accepted, so the very first dispatch decision is made against an
  observed Layer 1 state rather than an assumed one.

Absent configuration produces an absent subsystem, never a simulated one
standing in silently. A node with no `--safety-controller` has
`supervisor=None` and refuses safety queries; it does not quietly run a
simulator and report that everything is fine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import FaspHarness
from .edge.health import HealthRegistry
from .edge.lease import LeaderLease
from .edge.outbox import Outbox
from .fleet.adapter import FleetRegistry
from .fleet.model import Pose
from .fleet.service import MissionService
from .fleet.simulated import SimulatedFleetManager
from .layers import LayerGuard
from .protocol.errors import FaspError
from .realtime.scheduler import CyclicExecutor, OverrunPolicy
from .realtime.watchdog import DeadlineWatchdog
from .safety.drivers import ModbusSafetyController, SimulatedSafetyController
from .safety.interlock import SafetyFunction, SafetySupervisor
from .security.posture import DeploymentConfig, SecurityProfile, evaluate_posture
from .twin.kinematic import OccupancyGrid, SiteModel
from .twin.sync import TwinSync


@dataclass
class NodeConfig:
    """Everything a deployment declares, in one serialisable object."""

    name: str = "fasp-node"
    state_dir: Path = field(default_factory=lambda: Path(".fasp"))
    base_url: str = "http://127.0.0.1:8766"
    profile: SecurityProfile = SecurityProfile.DEVELOPMENT

    # Layer 1 observation
    safety_controller: dict[str, Any] | None = None
    """`{"kind": "modbus", "host": ..., "port": ..., "stop_coil": ...}` or
    `{"kind": "simulated"}`. Absent means this node observes no safety
    controller and will refuse to permit motion."""
    safety_poll_hz: float = 10.0
    safety_stale_after_s: float = 2.0
    max_speed_mps: float = 1.5
    safety_functions: list[dict[str, Any]] = field(default_factory=list)

    # Layer 3 fleets
    fleets: list[dict[str, Any]] = field(default_factory=list)
    """One entry per vendor: `{"kind": "vda5050"|"rest"|"simulated", ...}`."""

    # Site model / twin
    site_nodes: dict[str, list[float]] = field(default_factory=dict)
    blocked_regions: list[list[float]] = field(default_factory=list)
    grid_resolution_m: float = 0.5
    twin_tolerance_m: float = 1.0

    # High availability
    ha_enabled: bool = False
    lease_name: str = "fleet-coordinator"
    lease_ttl_s: float = 15.0
    node_id: str | None = None

    # Loops
    reconcile_hz: float = 1.0
    control_plane_watchdog_s: float = 10.0

    @classmethod
    def from_file(cls, path: Path) -> NodeConfig:
        """Load from JSON. Unknown keys are an error, not a shrug: a typo in
        a deployment file must not silently disable a safety-relevant
        setting."""
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise FaspError("schema.invalid", f"Cannot read the node configuration: {exc.__class__.__name__}.") from exc
        if not isinstance(document, dict):
            raise FaspError("schema.invalid", "A node configuration must be a JSON object.")
        known = {field_name for field_name in cls.__dataclass_fields__}
        unknown = sorted(set(document) - known)
        if unknown:
            raise FaspError("schema.invalid", f"Unknown node configuration keys: {unknown}. Refusing to start rather than ignoring them.")
        if "state_dir" in document:
            document["state_dir"] = Path(document["state_dir"])
        if "profile" in document:
            document["profile"] = SecurityProfile(str(document["profile"]))
        return cls(**document)


@dataclass
class Node:
    """A wired, running deployment and the loops that keep it current."""

    harness: FaspHarness
    config: NodeConfig
    registry: FleetRegistry
    health: HealthRegistry
    supervisor: SafetySupervisor | None = None
    missions: MissionService | None = None
    lease: LeaderLease | None = None
    outbox: Outbox | None = None
    twin: TwinSync | None = None
    site: SiteModel | None = None
    watchdog: DeadlineWatchdog | None = None
    _loops: list[CyclicExecutor] = field(default_factory=list)

    def start_loops(self) -> None:
        """Start the periodic work: safety polling and reconciliation.

        Both run on `CyclicExecutor`, so both have a period, a deadline, and
        a defined overrun policy -- and both produce timing evidence that
        the safety case and `/metrics` can read. The safety poll uses
        FAIL_SAFE: a supervisory loop that cannot keep up is itself a
        reason to stop, not a reason to fall behind quietly.
        """
        if self.supervisor is not None:
            poll = CyclicExecutor(
                1.0 / max(self.config.safety_poll_hz, 0.1),
                lambda index: self._safety_tick(),
                name="safety-poll",
                deadline_s=min(1.0 / max(self.config.safety_poll_hz, 0.1), self.config.safety_stale_after_s / 2.0),
                overrun_policy=OverrunPolicy.FAIL_SAFE,
                on_overrun=lambda index, late_ns: self._on_safety_overrun(late_ns),
            )
            self._loops.append(poll)
            poll.run_in_thread()
        if self.missions is not None:
            reconcile = CyclicExecutor(1.0 / max(self.config.reconcile_hz, 0.01), lambda index: self._reconcile_tick(), name="reconcile", overrun_policy=OverrunPolicy.SKIP)
            self._loops.append(reconcile)
            reconcile.run_in_thread()
        if self.lease is not None:
            self.lease.start()
        if self.watchdog is not None:
            self.watchdog.start()
        self.health.mark_started()

    def _safety_tick(self) -> None:
        if self.supervisor is not None:
            self.supervisor.poll()
        if self.watchdog is not None:
            self.watchdog.pet()

    def _on_safety_overrun(self, late_ns: int) -> None:
        if self.supervisor is not None:
            self.supervisor.demand_halt("safety-poll", f"Supervisory poll overran its deadline by {late_ns / 1e6:.0f}ms.", origin="supervisor")

    def _reconcile_tick(self) -> None:
        if self.missions is None:
            return
        if self.lease is not None and not self.lease.is_leader:
            # A standby reconciles nothing: two coordinators writing the
            # same mission rows is exactly what the lease exists to prevent.
            return
        try:
            self.missions.reconcile()
        except FaspError:
            return

    def stop(self) -> None:
        for loop in self._loops:
            loop.stop()
        if self.watchdog is not None:
            self.watchdog.stop()
        if self.lease is not None:
            self.lease.stop()
        self.harness.close()

    def timing_report(self) -> dict[str, Any]:
        from .realtime.scheduler import merge_reports

        return merge_reports(loop.report() for loop in self._loops)

    def overview(self) -> dict[str, Any]:
        return {
            "node": self.config.name,
            "system_id": self.harness.identity.system_id,
            "profile": self.config.profile.value,
            "health": self.health.snapshot(),
            "safety": self.supervisor.status() if self.supervisor else {"note": "no safety controller observed"},
            "fleet": self.missions.overview() if self.missions else {"note": "no fleet configured"},
            "timing": self.timing_report(),
            "outbox": self.outbox.depth() if self.outbox else {},
        }


def _build_supervisor(config: NodeConfig) -> SafetySupervisor | None:
    declared = config.safety_controller
    if not declared:
        return None
    kind = str(declared.get("kind", "")).lower()
    if kind == "modbus":
        driver: Any = ModbusSafetyController(
            str(declared["host"]),
            int(declared.get("port", 502)),
            unit_id=int(declared.get("unit_id", 1)),
            stop_coil=declared.get("stop_coil"),
            vendor=str(declared.get("vendor", "unspecified")),
            model=str(declared.get("model", "unspecified")),
        )
    elif kind == "simulated":
        driver = SimulatedSafetyController(stop_delay_s=float(declared.get("stop_delay_s", 0.0)))
    else:
        raise FaspError("schema.invalid", f"Unknown safety controller kind {kind!r}; use 'modbus' or 'simulated'.")

    supervisor = SafetySupervisor(driver, stale_after_s=config.safety_stale_after_s, max_speed_mps=config.max_speed_mps)
    for declaration in config.safety_functions:
        supervisor.register_function(
            SafetyFunction(
                id=str(declaration["id"]),
                description=str(declaration.get("description", "")),
                integrity_level=str(declaration.get("integrity_level", "unstated")),
                standard=str(declaration.get("standard", "unstated")),
                implemented_by=str(declaration.get("implemented_by", "unstated")),
                response_time_ms=declaration.get("response_time_ms"),
                demand_sources=tuple(declaration.get("demand_sources", ())),
                verified_by=tuple(declaration.get("verified_by", ())),
            )
        )
    return supervisor


def _build_registry(config: NodeConfig) -> FleetRegistry:
    registry = FleetRegistry()
    for declared in config.fleets:
        kind = str(declared.get("kind", "")).lower()
        name = str(declared.get("fleet", kind or "fleet"))
        if kind == "simulated":
            nodes = {node: Pose(*coordinates[:2], coordinates[2] if len(coordinates) > 2 else 0.0) for node, coordinates in (declared.get("nodes") or {}).items()}
            manager = SimulatedFleetManager(name, nodes=nodes)
            for vehicle in declared.get("vehicles", []):
                manager.add_vehicle(str(vehicle["id"]), pose=Pose(*(vehicle.get("pose") or [0.0, 0.0])[:2]), battery_ratio=float(vehicle.get("battery", 1.0)))
            registry.register(manager)
        elif kind == "vda5050":
            from .fleet.vda5050 import Vda5050Adapter

            publish = declared.get("publish")
            if not callable(publish):
                raise FaspError("schema.invalid", "A vda5050 fleet needs a `publish` callable; wire it to your MQTT client in code, not in the config file.")
            registry.register(Vda5050Adapter(name, publish, manufacturer=str(declared.get("manufacturer", "unknown"))))
        elif kind == "rest":
            from .fleet.rest import EndpointSpec, FieldMap, RestFleetAdapter

            endpoints = EndpointSpec(base_url=str(declared["base_url"]), headers=dict(declared.get("headers", {})))
            fields = FieldMap(**declared.get("fields", {}))
            registry.register(RestFleetAdapter(name, endpoints, fields=fields, vendor=str(declared.get("vendor", "unknown"))))
        else:
            raise FaspError("schema.invalid", f"Unknown fleet kind {kind!r}; use 'vda5050', 'rest', or 'simulated'.")
    return registry


def _build_site(config: NodeConfig) -> SiteModel | None:
    if not config.site_nodes:
        return None
    grid = OccupancyGrid(resolution_m=config.grid_resolution_m)
    for region in config.blocked_regions:
        if len(region) == 4:
            grid.block_rectangle(*region)
    return SiteModel(nodes={name: Pose(*coordinates[:2], coordinates[2] if len(coordinates) > 2 else 0.0) for name, coordinates in config.site_nodes.items()}, grid=grid)


def build_node(config: NodeConfig, *, adapter: Any = None, enforce_posture: bool = True) -> Node:
    """Wire a complete node. Refuses to build an unacceptable deployment."""
    supervisor = _build_supervisor(config)
    deployment = DeploymentConfig(
        profile=config.profile,
        host=config.base_url.split("://")[-1].split(":")[0],
        state_dir=config.state_dir,
        safety_controller=supervisor.driver.describe() if supervisor is not None and supervisor.driver is not None else None,
    )
    posture = evaluate_posture(deployment)
    if enforce_posture:
        posture.enforce()

    if supervisor is not None:
        # One sample before anything can ask for a dispatch decision, so the
        # very first one is made against an observed Layer 1 state rather
        # than an assumed one. `start_loops` keeps it fresh from here, and
        # `stale_after_s` is what catches a loop that later stops.
        supervisor.poll()

    registry = _build_registry(config)
    site = _build_site(config)
    twin = TwinSync(position_tolerance_m=config.twin_tolerance_m) if site is not None else None

    # The harness owns the database, so anything that needs durable state
    # is built after it and handed its connection -- one file, one lock,
    # one set of migrations.
    harness = FaspHarness(config.state_dir, config.name, config.base_url, adapter, supervisor=supervisor, layer_guard=LayerGuard())
    lease = LeaderLease(harness.db, config.lease_name, node_id=config.node_id, ttl_s=config.lease_ttl_s) if config.ha_enabled else None
    outbox = Outbox(harness.db)

    missions = MissionService(
        harness.db,
        registry,
        audit=harness.audit,
        supervisor=supervisor,
        site=site,
        twin=twin,
        reservations=harness.reservations,
        lease=lease,
    )
    harness.missions = missions

    health = HealthRegistry(node_id=config.node_id or config.name)
    health.register("database", lambda: (bool(harness.db.read_one("SELECT 1 AS ok")), "sqlite reachable"), critical=True)
    health.register("audit-chain", lambda: (harness.audit.verify()[0], "hash chain verifies"), critical=False)
    if supervisor is not None:
        health.register("safety-controller", lambda: (supervisor.current_status().reachable, supervisor.current_status().detail or "controller reachable"))
    if lease is not None:
        # Leadership affects readiness, never liveness: a healthy standby
        # must not be restarted for the crime of being a standby.
        health.register("leadership", lambda: (lease.is_leader, "holds the coordinator lease" if lease.is_leader else "standby"), critical=False)

    watchdog = None
    if supervisor is not None:
        watchdog = DeadlineWatchdog(
            "control-plane",
            config.control_plane_watchdog_s,
            lambda detail: supervisor.demand_halt("control-plane-watchdog", detail, origin="watchdog"),
        )

    return Node(
        harness=harness,
        config=config,
        registry=registry,
        health=health,
        supervisor=supervisor,
        missions=missions,
        lease=lease,
        outbox=outbox,
        twin=twin,
        site=site,
        watchdog=watchdog,
    )
