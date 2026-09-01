"""VDA 5050: the interface a multi-vendor site most likely already speaks.

VDA 5050 ("Interface for the communication between automated guided
vehicles and a master control") is the VDA/VDMA standard that exists
precisely because every AGV vendor had its own protocol. If a coordinator
is going to speak one vendor-neutral vehicle interface, this is it.

Implemented here: the message set (`order`, `instantActions`, `state`,
`connection`, `factsheet`, `visualization`), the topic structure, the
header contract, and -- the part that is easy to get wrong and expensive to
get wrong -- the *order update rules*:

- nodes carry even `sequenceId`s and edges odd ones, alternating, starting
  at the first node, so a vehicle can order-check a message it received out
  of sequence;
- an order is split into a **base** (committed, the vehicle will traverse
  it) and a **horizon** (predicted, may still change). Only the horizon may
  be rewritten;
- an update to a running order must carry the same `orderId` with a
  strictly greater `orderUpdateId`, and must start at the vehicle's last
  released base node. Getting this wrong is how a vehicle ends up rejecting
  an update mid-aisle and stopping, so `OrderBuilder.update()` enforces it
  rather than trusting the caller;
- a genuinely different route is a new `orderId`, not an update.

Transport is deliberately injected. VDA 5050 runs over MQTT in practice,
but the message construction, validation, and state mapping are the part
worth owning; which MQTT client a site uses is theirs to choose. Pass any
callable that publishes `(topic, payload)` and this works with paho, with
an existing broker session, or with an in-memory double in a test.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..protocol.errors import FaspError
from ..timestamps import now, stamp
from .model import ErrorLevel, Mission, MissionState, OperatingMode, Pose, StepKind, VehicleCapabilities, VehicleState

INTERFACE_NAME = "uagv"
PROTOCOL_VERSION = "2.0.0"
MAJOR_VERSION = "v2"

# Mission step -> VDA 5050 action type. `move` has no action: movement is
# expressed by the node/edge graph itself, which is the standard's whole
# model and the reason a coordinator never sends a trajectory.
ACTION_TYPES: dict[StepKind, str | None] = {
    StepKind.MOVE: None,
    StepKind.PICK: "pick",
    StepKind.DROP: "drop",
    StepKind.CHARGE: "startCharging",
    StepKind.DOCK: "dock",
    StepKind.UNDOCK: "undock",
    StepKind.WAIT: "wait",
    StepKind.CUSTOM: "customAction",
}

# Instant actions a master control may send at any time (VDA 5050 6.9).
# `startPause`/`stopPause` and `cancelOrder` are requests to the vehicle's
# own controller -- note that none of them is a safety function, and that
# the standard is explicit that its emergency stop is a hardware matter.
INSTANT_ACTIONS = frozenset({"startPause", "stopPause", "cancelOrder", "factsheetRequest", "stateRequest", "initPosition"})


class Vda5050Error(FaspError):
    def __init__(self, detail: str, *, code: str = "schema.invalid") -> None:
        super().__init__(code, detail)


def topic(manufacturer: str, serial_number: str, subject: str, *, interface: str = INTERFACE_NAME) -> str:
    """`uagv/v2/<manufacturer>/<serialNumber>/<subject>` (VDA 5050 5.2)."""
    for part, name in ((manufacturer, "manufacturer"), (serial_number, "serialNumber"), (subject, "topic")):
        if not part or "/" in part or "+" in part or "#" in part:
            raise Vda5050Error(f"VDA 5050 {name} must be non-empty and free of MQTT wildcards and separators.")
    return f"{interface}/{MAJOR_VERSION}/{manufacturer}/{serial_number}/{subject}"


class HeaderSequence:
    """Per-vehicle `headerId`, monotonic and gap-free.

    The standard requires it to increase per topic so a receiver can detect
    loss. Kept here, per vehicle, under a lock, because two threads
    dispatching to the same vehicle must not both mint the same id.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}

    def next(self, key: str) -> int:
        with self._lock:
            value = self._counters.get(key, 0) + 1
            self._counters[key] = value
            return value


def header(header_id: int, manufacturer: str, serial_number: str) -> dict[str, Any]:
    return {
        "headerId": header_id,
        "timestamp": stamp(now()),
        "version": PROTOCOL_VERSION,
        "manufacturer": manufacturer,
        "serialNumber": serial_number,
    }


@dataclass
class OrderBuilder:
    """Builds and updates VDA 5050 orders with the sequencing rules enforced."""

    manufacturer: str
    serial_number: str
    sequence: HeaderSequence = field(default_factory=HeaderSequence)

    def build(self, mission: Mission, *, order_update_id: int = 0, base_nodes: int | None = None) -> dict[str, Any]:
        """Turn a goal-level mission into an order.

        `base_nodes` splits the route: the first N nodes are the committed
        base, the rest are the horizon the coordinator may still revise. The
        default commits everything, which is right for a short mission and
        wrong for a long one -- hence the parameter.
        """
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        sequence_id = 0
        move_steps = [step for step in mission.steps if step.node_id or step.pose]
        if not move_steps:
            raise Vda5050Error("A VDA 5050 order needs at least one node; this mission has no place to go.")
        limit = len(move_steps) if base_nodes is None else max(1, min(base_nodes, len(move_steps)))

        for index, step in enumerate(move_steps):
            released = index < limit
            node_id = step.node_id or f"{mission.mission_id}-n{index}"
            node: dict[str, Any] = {
                "nodeId": node_id,
                "sequenceId": sequence_id,
                "released": released,
                "actions": _actions_for(step, mission),
            }
            if step.pose is not None:
                node["nodePosition"] = {"x": step.pose.x, "y": step.pose.y, "theta": step.pose.theta, "mapId": step.pose.map_id, "allowedDeviationXY": float(mission.constraints.get("allowed_deviation_xy", 0.2))}
            node["nodeDescription"] = step.kind.value
            nodes.append(node)
            sequence_id += 1
            if index + 1 < len(move_steps):
                next_step = move_steps[index + 1]
                edges.append(
                    {
                        "edgeId": f"{node_id}->{next_step.node_id or f'{mission.mission_id}-n{index + 1}'}",
                        "sequenceId": sequence_id,
                        "released": released and index + 1 < limit,
                        "startNodeId": node_id,
                        "endNodeId": next_step.node_id or f"{mission.mission_id}-n{index + 1}",
                        "actions": [],
                        **({"maxSpeed": float(mission.constraints["max_speed_mps"])} if "max_speed_mps" in mission.constraints else {}),
                    }
                )
                sequence_id += 1

        return {
            **header(self.sequence.next(f"{self.serial_number}/order"), self.manufacturer, self.serial_number),
            "orderId": mission.mission_id,
            "orderUpdateId": order_update_id,
            "nodes": nodes,
            "edges": edges,
            **({"zoneSetId": mission.constraints["zone_set_id"]} if "zone_set_id" in mission.constraints else {}),
        }

    def update(self, previous: dict[str, Any], mission: Mission, *, last_released_node_id: str, base_nodes: int | None = None) -> dict[str, Any]:
        """Produce a valid *update* to a running order.

        Enforces the two rules a vehicle will reject an update for: the
        `orderId` must match, and the update must begin at the node the
        vehicle last released. Building this wrong is not a cosmetic
        problem -- the vehicle rejects the order and stops where it is.
        """
        if previous.get("orderId") != mission.mission_id:
            raise Vda5050Error("An order update must keep the same orderId; a different route is a new order, not an update.")
        order = self.build(mission, order_update_id=int(previous.get("orderUpdateId", 0)) + 1, base_nodes=base_nodes)
        if not order["nodes"] or order["nodes"][0]["nodeId"] != last_released_node_id:
            raise Vda5050Error(f"An order update must start at the vehicle's last released base node ({last_released_node_id!r}).")
        return order

    def instant_action(self, action_type: str, parameters: dict[str, Any] | None = None, *, blocking: str = "HARD") -> dict[str, Any]:
        if action_type not in INSTANT_ACTIONS:
            raise Vda5050Error(f"{action_type!r} is not a VDA 5050 instant action.")
        if blocking not in {"NONE", "SOFT", "HARD"}:
            raise Vda5050Error("blockingType must be NONE, SOFT, or HARD.")
        return {
            **header(self.sequence.next(f"{self.serial_number}/instantActions"), self.manufacturer, self.serial_number),
            "actions": [
                {
                    "actionType": action_type,
                    "actionId": f"{action_type}-{self.sequence.next('action')}",
                    "blockingType": blocking,
                    "actionParameters": [{"key": key, "value": value} for key, value in sorted((parameters or {}).items())],
                }
            ],
        }


def _actions_for(step: Any, mission: Mission) -> list[dict[str, Any]]:
    action_type = ACTION_TYPES.get(step.kind)
    if action_type is None:
        return []
    parameters = dict(step.parameters)
    if step.kind is StepKind.CUSTOM:
        action_type = str(parameters.pop("action_type", "customAction"))
    return [
        {
            "actionType": action_type,
            "actionId": f"{mission.mission_id}-{step.step_id}",
            "blockingType": "HARD" if step.blocking else "NONE",
            "actionDescription": step.kind.value,
            "actionParameters": [{"key": key, "value": value} for key, value in sorted(parameters.items())],
        }
    ]


def parse_state(payload: dict[str, Any], *, fleet: str, expected_serial: str | None = None) -> VehicleState:
    """Map a VDA 5050 `state` message onto the neutral `VehicleState`.

    Note `safety_estop_active`: the standard reports E-stop under
    `safetyState.eStop` with values `AUTOACK`/`MANUAL`/`REMOTE`/`NONE`.
    Anything but `NONE` means an E-stop is engaged, which is treated here as
    a hard bar on dispatch -- observed, never cleared.
    """
    serial = str(payload.get("serialNumber", ""))
    if expected_serial is not None and serial != expected_serial:
        raise Vda5050Error("VDA 5050 state message serialNumber does not match the vehicle it was received for.")
    safety = payload.get("safetyState") or {}
    battery = payload.get("batteryState") or {}
    position = payload.get("agvPosition") or {}
    velocity = payload.get("velocity") or {}
    errors = tuple(
        {
            "code": str(error.get("errorType", "unknown")),
            "level": ErrorLevel.FATAL.value if str(error.get("errorLevel", "")).upper() == "FATAL" else ErrorLevel.WARNING.value,
            "description": str(error.get("errorDescription", ""))[:200],
        }
        for error in payload.get("errors") or []
        if isinstance(error, dict)
    )
    try:
        mode = OperatingMode(str(payload.get("operatingMode", "AUTOMATIC")).upper())
    except ValueError:
        mode = OperatingMode.SERVICE

    pose = None
    if position.get("positionInitialized") and "x" in position and "y" in position:
        pose = Pose(float(position["x"]), float(position["y"]), float(position.get("theta", 0.0)), str(position.get("mapId", "default")))

    charge = battery.get("batteryCharge")
    return VehicleState(
        vehicle_id=serial,
        fleet=fleet,
        online=True,
        operating_mode=mode,
        pose=pose,
        battery_ratio=max(0.0, min(1.0, float(charge) / 100.0)) if isinstance(charge, (int, float)) else 0.0,
        charging=bool(battery.get("charging", False)),
        driving=bool(payload.get("driving", False)),
        paused=bool(payload.get("paused", False)),
        errors=errors,
        current_mission_id=str(payload["orderId"]) if payload.get("orderId") else None,
        velocity_mps=float((velocity.get("vx") or 0.0) ** 2 + (velocity.get("vy") or 0.0) ** 2) ** 0.5,
        safety_estop_active=str(safety.get("eStop", "NONE")).upper() != "NONE",
        protective_field_violated=bool(safety.get("fieldViolation", False)),
        vendor_state={"lastNodeId": payload.get("lastNodeId"), "orderUpdateId": payload.get("orderUpdateId"), "actionStates": payload.get("actionStates", [])},
    )


def mission_state_from(payload: dict[str, Any], mission_id: str) -> MissionState:
    """Derive a mission's state from a vehicle's VDA 5050 state message.

    A vehicle does not report "mission failed"; it reports node states,
    action states, and errors, and the coordinator concludes. Concluding it
    in one place beats every call site guessing.
    """
    if str(payload.get("orderId", "")) != mission_id:
        # The vehicle has moved on. Only a fatal error still tells us
        # anything about our order; otherwise it finished.
        return MissionState.COMPLETED
    actions = [action for action in payload.get("actionStates") or [] if isinstance(action, dict)]
    if any(str(action.get("actionStatus", "")).upper() == "FAILED" for action in actions):
        return MissionState.FAILED
    if any(str(error.get("errorLevel", "")).upper() == "FATAL" for error in payload.get("errors") or [] if isinstance(error, dict)):
        return MissionState.FAILED
    outstanding = bool(payload.get("nodeStates")) or bool(payload.get("edgeStates"))
    unfinished_actions = any(str(action.get("actionStatus", "")).upper() not in {"FINISHED", "FAILED"} for action in actions)
    if outstanding or unfinished_actions:
        return MissionState.PAUSED if payload.get("paused") else MissionState.RUNNING
    return MissionState.COMPLETED


def parse_factsheet(payload: dict[str, Any], *, fleet: str) -> VehicleCapabilities:
    """Map a VDA 5050 `factsheet` onto neutral capabilities.

    The factsheet is how a vendor-agnostic coordinator learns what a vehicle
    can do without being configured per vehicle -- which is the difference
    between adding a robot and redeploying the coordinator.
    """
    del fleet
    physical = payload.get("physicalParameters") or {}
    type_specification = payload.get("typeSpecification") or {}
    load = payload.get("loadSpecification") or {}
    protocol_features = payload.get("protocolFeatures") or {}
    supported = {StepKind.MOVE}
    for action in protocol_features.get("agvActions") or []:
        if not isinstance(action, dict):
            continue
        for kind, action_type in ACTION_TYPES.items():
            if action_type and str(action.get("actionType", "")) == action_type:
                supported.add(kind)
    load_sets = load.get("loadSets") or []
    payload_kg = max((float(item.get("maxWeight", 0.0)) for item in load_sets if isinstance(item, dict)), default=0.0)
    return VehicleCapabilities(
        max_speed_mps=float(physical.get("speedMax", 1.5)),
        payload_kg=payload_kg,
        footprint_m=(float(physical.get("length", 1.0)), float(physical.get("width", 0.6))),
        supported_steps=tuple(sorted(supported, key=lambda item: item.value)),
        vendor=str(payload.get("manufacturer", "unknown")),
        model=str(type_specification.get("seriesName", payload.get("serialNumber", "unknown"))),
        interface=f"VDA 5050 {payload.get('version', PROTOCOL_VERSION)}",
    )


class Vda5050Adapter:
    """A `FleetManagerAdapter` speaking VDA 5050 over an injected transport.

    State arrives asynchronously (the vehicle publishes; nobody polls), so
    this class is a cache with a freshness rule: a vehicle whose last state
    message is older than `offline_after_s` is reported offline rather than
    reported stale, because a scheduler that treats a silent vehicle as
    idle will dispatch to a robot that is not there.
    """

    def __init__(
        self,
        fleet: str,
        publish: Callable[[str, str], None],
        *,
        manufacturer: str = "unknown",
        offline_after_s: float = 15.0,
    ) -> None:
        self.fleet = fleet
        self.publish = publish
        self.manufacturer = manufacturer
        self.offline_after_s = offline_after_s
        self._lock = threading.RLock()
        self._states: dict[str, tuple[float, VehicleState]] = {}
        self._raw: dict[str, dict[str, Any]] = {}
        self._capabilities: dict[str, VehicleCapabilities] = {}
        self._orders: dict[str, dict[str, Any]] = {}
        self._builders: dict[str, OrderBuilder] = {}
        self._connections: dict[str, str] = {}

    # -- inbound ---------------------------------------------------------
    def on_message(self, message_topic: str, payload: str | bytes | dict[str, Any]) -> None:
        """Feed one received MQTT message in. Never raises on bad input:
        a malformed message from one vehicle must not stop the others."""
        try:
            body = payload if isinstance(payload, dict) else json.loads(payload)
            if not isinstance(body, dict):
                return
            subject = message_topic.rsplit("/", 1)[-1]
            if subject == "state":
                self._ingest_state(body)
            elif subject == "factsheet":
                serial = str(body.get("serialNumber", ""))
                if serial:
                    with self._lock:
                        self._capabilities[serial] = parse_factsheet(body, fleet=self.fleet)
            elif subject == "connection":
                serial = str(body.get("serialNumber", ""))
                if serial:
                    with self._lock:
                        self._connections[serial] = str(body.get("connectionState", "OFFLINE")).upper()
        except (ValueError, TypeError, FaspError):
            return

    def _ingest_state(self, body: dict[str, Any]) -> None:
        import time

        state = parse_state(body, fleet=self.fleet)
        if not state.vehicle_id:
            return
        with self._lock:
            self._states[state.vehicle_id] = (time.monotonic(), state)
            self._raw[state.vehicle_id] = body

    # -- adapter interface -------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "vendor_interface": "VDA 5050",
            "interface_version": PROTOCOL_VERSION,
            "manufacturer": self.manufacturer,
            "transport": "injected publish callable (MQTT in a real deployment)",
            "vehicles_seen": len(self._states),
            "capabilities": ["dispatch", "cancel", "pause", "observe", "request_stop"],
            "not_provided": ["emergency stop (hardware only, per VDA 5050 and ISO 3691-4)", "trajectory control", "safety field configuration"],
        }

    def _fresh(self, vehicle_id: str) -> VehicleState | None:
        import time

        with self._lock:
            entry = self._states.get(vehicle_id)
            connection = self._connections.get(vehicle_id, "ONLINE")
        if entry is None:
            return None
        seen_at, state = entry
        age = time.monotonic() - seen_at
        online = age <= self.offline_after_s and connection == "ONLINE"
        if online:
            return state
        return VehicleState(**{**state.__dict__, "online": False})

    def list_vehicles(self) -> list[VehicleState]:
        with self._lock:
            ids = sorted(self._states)
        return [state for state in (self._fresh(vehicle_id) for vehicle_id in ids) if state is not None]

    def vehicle_state(self, vehicle_id: str) -> VehicleState:
        state = self._fresh(vehicle_id)
        if state is None:
            raise Vda5050Error(f"No VDA 5050 state has been received for vehicle {vehicle_id!r}.", code="capability.unavailable")
        return state

    def capabilities(self, vehicle_id: str) -> VehicleCapabilities:
        with self._lock:
            known = self._capabilities.get(vehicle_id)
        if known is not None:
            return known
        # No factsheet yet: ask for one, and answer conservatively in the
        # meantime -- movement only, which is the one thing every AGV does.
        self.send_instant_action(vehicle_id, "factsheetRequest")
        return VehicleCapabilities(supported_steps=(StepKind.MOVE,), vendor=self.manufacturer, interface="VDA 5050 (factsheet pending)")

    def _builder(self, vehicle_id: str) -> OrderBuilder:
        with self._lock:
            builder = self._builders.get(vehicle_id)
            if builder is None:
                builder = self._builders[vehicle_id] = OrderBuilder(self.manufacturer, vehicle_id)
            return builder

    def dispatch(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        order = self._builder(vehicle_id).build(mission, base_nodes=mission.constraints.get("base_nodes"))
        self.publish(topic(self.manufacturer, vehicle_id, "order"), json.dumps(order, separators=(",", ":")))
        with self._lock:
            self._orders[mission.mission_id] = order
        return {"interface": "VDA 5050", "orderId": order["orderId"], "orderUpdateId": order["orderUpdateId"], "nodes": len(order["nodes"]), "edges": len(order["edges"])}

    def update_order(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        """Revise a running order's horizon without restarting the mission."""
        with self._lock:
            previous = self._orders.get(mission.mission_id)
            raw = self._raw.get(vehicle_id) or {}
        if previous is None:
            raise Vda5050Error("No previous order to update for this mission.")
        last_released = str(raw.get("lastNodeId") or previous["nodes"][0]["nodeId"])
        order = self._builder(vehicle_id).update(previous, mission, last_released_node_id=last_released, base_nodes=mission.constraints.get("base_nodes"))
        self.publish(topic(self.manufacturer, vehicle_id, "order"), json.dumps(order, separators=(",", ":")))
        with self._lock:
            self._orders[mission.mission_id] = order
        return {"orderId": order["orderId"], "orderUpdateId": order["orderUpdateId"]}

    def send_instant_action(self, vehicle_id: str, action_type: str, parameters: dict[str, Any] | None = None) -> bool:
        try:
            message = self._builder(vehicle_id).instant_action(action_type, parameters)
            self.publish(topic(self.manufacturer, vehicle_id, "instantActions"), json.dumps(message, separators=(",", ":")))
        except (FaspError, OSError):
            return False
        return True

    def cancel(self, mission_id: str) -> bool:
        with self._lock:
            order = self._orders.get(mission_id)
        if order is None:
            return False
        return self.send_instant_action(str(order["serialNumber"]), "cancelOrder")

    def mission_state(self, mission_id: str) -> MissionState:
        with self._lock:
            order = self._orders.get(mission_id)
            raw = self._raw.get(str(order["serialNumber"])) if order else None
        if order is None:
            raise Vda5050Error(f"Unknown mission {mission_id!r}.", code="capability.unavailable")
        if raw is None:
            return MissionState.ASSIGNED
        return mission_state_from(raw, mission_id)

    def request_stop(self, vehicle_id: str, reason: str) -> bool:
        """`startPause` -- a request to the vehicle's controller.

        Emphatically not an emergency stop. VDA 5050 has no such message,
        deliberately: the standard treats emergency stop as a hardware
        function, which is the same position `fasp_harness.layers` takes.
        """
        return self.send_instant_action(vehicle_id, "startPause", {"reason": str(reason)[:120]})
