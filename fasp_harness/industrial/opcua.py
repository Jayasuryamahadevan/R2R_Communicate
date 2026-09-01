"""OPC UA: the Layer 4 boundary, read-mostly and explicitly allowlisted.

OPC UA is how a coordinator talks to the rest of the plant -- the MES that
issues production orders, the SCADA historian, the machine that reports it
is ready for a pick. It is also the interface most likely to be pointed at
something that moves, which is why the write path here is built the way it
is.

`OpcUaClient` is the whole boundary. `SimulatedOpcUaClient` implements it
over a deterministic in-process address space (server object, DeviceSet,
per-device variables -- the shape the companion specifications use), so
every code path is exercised in CI with no server, no certificates, and no
network. `AsyncuaClient` binds to the `asyncua` library when it is
installed, and raises `capability.unavailable` when it is not, rather than
degrading to something that looks like it worked.

Reads are unrestricted. Writes require a `WriteAllowlist`: an explicit set
of node ids an operator has enumerated, with a reason recorded for each,
and a hard refusal for any node whose browse path or id looks like a safety
function. The default allowlist is empty, so the out-of-the-box behaviour
of this client is that it cannot write anything at all.

Certificate handling, user tokens, and the binary transport belong to the
real stack. What is owned here is the *policy*: what may be written, by
whom, and with what recorded justification.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Protocol, runtime_checkable

from ..layers import LayerGuard, LayerViolation
from ..protocol.errors import FaspError
from ..timestamps import stamp


class StatusCode(IntEnum):
    """The handful of OPC UA status codes this layer distinguishes."""

    GOOD = 0x00000000
    UNCERTAIN = 0x40000000
    BAD = 0x80000000
    BAD_NODE_ID_UNKNOWN = 0x80340000
    BAD_NOT_READABLE = 0x803A0000
    BAD_NOT_WRITABLE = 0x803B0000
    BAD_USER_ACCESS_DENIED = 0x801F0000
    BAD_OUT_OF_RANGE = 0x803C0000

    @property
    def good(self) -> bool:
        return self is StatusCode.GOOD


@dataclass(frozen=True)
class NodeId:
    """`ns=<namespace>;<type>=<identifier>`, as OPC UA writes it."""

    namespace: int
    identifier: str | int
    id_type: str = "s"

    def __str__(self) -> str:
        return f"ns={self.namespace};{self.id_type}={self.identifier}"

    @classmethod
    def parse(cls, value: str | NodeId) -> NodeId:
        if isinstance(value, NodeId):
            return value
        text = str(value).strip()
        namespace = 0
        if text.startswith("ns="):
            namespace_text, _, text = text[3:].partition(";")
            try:
                namespace = int(namespace_text)
            except ValueError as exc:
                raise FaspError("schema.invalid", "OPC UA NodeId namespace must be an integer.") from exc
        id_type, separator, identifier = text.partition("=")
        if not separator or id_type not in {"i", "s", "g", "b"}:
            raise FaspError("schema.invalid", "OPC UA NodeId must be 'ns=N;s=Name' or 'i=1234'.")
        return cls(namespace, int(identifier) if id_type == "i" and identifier.isdigit() else identifier, id_type)


@dataclass(frozen=True)
class DataValue:
    """A value with its status and source timestamp.

    All three, always. An OPC UA value without its status code is how a
    stale or uncertain reading becomes an authoritative one somewhere
    downstream.
    """

    value: Any
    status: StatusCode = StatusCode.GOOD
    source_timestamp: str = field(default_factory=stamp)
    node_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "value": self.value, "status": self.status.name, "good": self.status.good, "source_timestamp": self.source_timestamp}


@runtime_checkable
class OpcUaClient(Protocol):
    def connect(self) -> None: ...

    def disconnect(self) -> None: ...

    def read(self, node_ids: list[str]) -> list[DataValue]: ...

    def browse(self, node_id: str) -> list[dict[str, Any]]: ...

    def write(self, node_id: str, value: Any) -> StatusCode: ...

    def describe(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class WriteRule:
    node_id: str
    reason: str
    allowed_types: tuple[type, ...] = (bool, int, float, str)
    minimum: float | None = None
    maximum: float | None = None


class WriteAllowlist:
    """Which OPC UA nodes may be written, and why. Empty by default.

    Range bounds are part of the rule rather than a downstream check: a
    setpoint written outside its engineering range is the OPC UA equivalent
    of an unvalidated input, and the allowlist is the one place that
    definitely runs.
    """

    def __init__(self, rules: list[WriteRule] | None = None, *, guard: LayerGuard | None = None) -> None:
        self.guard = guard or LayerGuard()
        self._rules: dict[str, WriteRule] = {}
        for rule in rules or ():
            self.allow(rule)

    def allow(self, rule: WriteRule) -> WriteRule:
        """Add a rule, refusing any node that names a Layer 1 function."""
        reason = self.guard.reserved_reason(str(rule.node_id))
        if reason is not None:
            raise LayerViolation(f"OPC UA node {rule.node_id!r} names a Layer 1 safety function. {reason} It cannot be added to a write allowlist.")
        self._rules[str(NodeId.parse(rule.node_id))] = rule
        return rule

    def check(self, node_id: str, value: Any) -> WriteRule:
        key = str(NodeId.parse(node_id))
        rule = self._rules.get(key)
        if rule is None:
            raise FaspError("auth.not_authorized", f"OPC UA node {key} is not on the write allowlist. Writes are deny-by-default.")
        if not isinstance(value, rule.allowed_types) or isinstance(value, bool) and bool not in rule.allowed_types:
            raise FaspError("schema.invalid", f"OPC UA node {key} does not accept a {type(value).__name__} value.")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if rule.minimum is not None and value < rule.minimum:
                raise FaspError("schema.invalid", f"Value {value} is below node {key}'s configured minimum {rule.minimum}.")
            if rule.maximum is not None and value > rule.maximum:
                raise FaspError("schema.invalid", f"Value {value} is above node {key}'s configured maximum {rule.maximum}.")
        return rule

    def describe(self) -> list[dict[str, Any]]:
        return [{"node_id": rule.node_id, "reason": rule.reason, "minimum": rule.minimum, "maximum": rule.maximum} for rule in sorted(self._rules.values(), key=lambda item: item.node_id)]


@dataclass
class SimulatedNode:
    node_id: str
    browse_name: str
    value: Any = None
    node_class: str = "Variable"
    writable: bool = False
    children: list[str] = field(default_factory=list)
    data_type: str = "Double"


class SimulatedOpcUaClient:
    """A deterministic OPC UA address space, complete enough to test against.

    Structured like a real server -- `Objects/Server`, `Objects/DeviceSet`,
    a folder per device with typed variables -- so browse-path handling,
    subscription behaviour, and allowlist enforcement are exercised for real
    rather than mocked away.
    """

    def __init__(self, *, allowlist: WriteAllowlist | None = None, endpoint: str = "opc.tcp://simulated:4840/fasp/") -> None:
        self.endpoint = endpoint
        self.allowlist = allowlist or WriteAllowlist()
        self.connected = False
        self._lock = threading.RLock()
        self._nodes: dict[str, SimulatedNode] = {}
        self._subscriptions: dict[str, list[Callable[[DataValue], None]]] = {}
        self.write_log: list[dict[str, Any]] = []
        self._seed_address_space()

    def _seed_address_space(self) -> None:
        self._add(SimulatedNode("ns=0;i=85", "Objects", node_class="Object", children=["ns=0;i=2253", "ns=2;s=DeviceSet"]))
        self._add(SimulatedNode("ns=0;i=2253", "Server", node_class="Object", children=["ns=0;i=2259"]))
        self._add(SimulatedNode("ns=0;i=2259", "ServerStatus.State", value=0, data_type="Int32"))
        self._add(SimulatedNode("ns=2;s=DeviceSet", "DeviceSet", node_class="Object", children=[]))

    def _add(self, node: SimulatedNode) -> SimulatedNode:
        with self._lock:
            self._nodes[str(NodeId.parse(node.node_id))] = node
        return node

    def add_device(self, name: str, variables: dict[str, Any], *, writable: tuple[str, ...] = ()) -> str:
        """Add a device folder with typed variables under `DeviceSet`."""
        device_id = f"ns=2;s={name}"
        children: list[str] = []
        for variable, value in sorted(variables.items()):
            variable_id = f"ns=2;s={name}.{variable}"
            self._add(SimulatedNode(variable_id, variable, value=value, writable=variable in writable, data_type=type(value).__name__))
            children.append(variable_id)
        self._add(SimulatedNode(device_id, name, node_class="Object", children=children))
        with self._lock:
            self._nodes["ns=2;s=DeviceSet"].children.append(device_id)
        return device_id

    def set_value(self, node_id: str, value: Any) -> None:
        """Change a value the way the *plant* would -- bypassing the
        allowlist, which governs what this client may write, not what the
        world may do."""
        key = str(NodeId.parse(node_id))
        with self._lock:
            node = self._nodes.get(key)
            if node is None:
                raise FaspError("schema.invalid", f"Unknown simulated node {key}.")
            node.value = value
            handlers = list(self._subscriptions.get(key, ()))
        for handler in handlers:
            handler(DataValue(value, StatusCode.GOOD, stamp(), key))

    # -- client interface ---------------------------------------------------
    def connect(self) -> None:
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def _require_connected(self) -> None:
        if not self.connected:
            raise FaspError("transport.unreachable", "OPC UA client is not connected.")

    def read(self, node_ids: list[str]) -> list[DataValue]:
        self._require_connected()
        values: list[DataValue] = []
        with self._lock:
            for raw in node_ids:
                key = str(NodeId.parse(raw))
                node = self._nodes.get(key)
                if node is None:
                    values.append(DataValue(None, StatusCode.BAD_NODE_ID_UNKNOWN, stamp(), key))
                elif node.node_class != "Variable":
                    values.append(DataValue(None, StatusCode.BAD_NOT_READABLE, stamp(), key))
                else:
                    values.append(DataValue(node.value, StatusCode.GOOD, stamp(), key))
        return values

    def browse(self, node_id: str = "ns=0;i=85") -> list[dict[str, Any]]:
        self._require_connected()
        key = str(NodeId.parse(node_id))
        with self._lock:
            node = self._nodes.get(key)
            if node is None:
                raise FaspError("schema.invalid", f"Unknown OPC UA node {key}.")
            return [
                {"node_id": child, "browse_name": self._nodes[child].browse_name, "node_class": self._nodes[child].node_class, "data_type": self._nodes[child].data_type}
                for child in node.children
                if child in self._nodes
            ]

    def write(self, node_id: str, value: Any) -> StatusCode:
        """Write through the allowlist. Deny-by-default and audited."""
        self._require_connected()
        key = str(NodeId.parse(node_id))
        rule = self.allowlist.check(key, value)
        with self._lock:
            node = self._nodes.get(key)
            if node is None:
                return StatusCode.BAD_NODE_ID_UNKNOWN
            if not node.writable:
                return StatusCode.BAD_NOT_WRITABLE
            node.value = value
            self.write_log.append({"node_id": key, "value": value, "reason": rule.reason, "at": stamp()})
            handlers = list(self._subscriptions.get(key, ()))
        for handler in handlers:
            handler(DataValue(value, StatusCode.GOOD, stamp(), key))
        return StatusCode.GOOD

    def subscribe(self, node_id: str, handler: Callable[[DataValue], None]) -> Callable[[], None]:
        """Monitored item. Returns its own unsubscribe callable."""
        key = str(NodeId.parse(node_id))
        with self._lock:
            self._subscriptions.setdefault(key, []).append(handler)

        def unsubscribe() -> None:
            with self._lock:
                handlers = self._subscriptions.get(key, [])
                if handler in handlers:
                    handlers.remove(handler)

        return unsubscribe

    def describe(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "implementation": "simulated",
            "real_server": False,
            "security_policy": "none (simulation)",
            "nodes": len(self._nodes),
            "write_allowlist": self.allowlist.describe(),
        }


class AsyncuaClient:
    """Binding to the `asyncua` library, subject to the same allowlist.

    A synchronous facade over an async library, because the harness is
    synchronous and pretending otherwise would push asyncio through every
    caller. `asyncua` ships a sync wrapper for exactly this; if it is not
    installed, this raises rather than degrading to something that looks
    like it worked.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        allowlist: WriteAllowlist | None = None,
        security_string: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        try:
            from asyncua.sync import Client  # type: ignore[import-not-found]
        except ImportError as exc:
            raise FaspError("capability.unavailable", "The `asyncua` package is not installed; install it or use SimulatedOpcUaClient.") from exc
        self.endpoint = endpoint
        self.allowlist = allowlist or WriteAllowlist()
        self.security_string = security_string
        self._client = Client(url=endpoint, timeout=timeout_s)
        if username:
            self._client.set_user(username)
        if password:
            self._client.set_password(password)
        self.connected = False

    def connect(self) -> None:
        if self.security_string:
            self._client.set_security_string(self.security_string)
        self._client.connect()
        self.connected = True

    def disconnect(self) -> None:
        try:
            self._client.disconnect()
        finally:
            self.connected = False

    def read(self, node_ids: list[str]) -> list[DataValue]:
        values: list[DataValue] = []
        for raw in node_ids:
            key = str(NodeId.parse(raw))
            try:
                values.append(DataValue(self._client.get_node(key).read_value(), StatusCode.GOOD, stamp(), key))
            except Exception:  # noqa: BLE001 - vendor stacks raise a wide variety
                values.append(DataValue(None, StatusCode.BAD, stamp(), key))
        return values

    def browse(self, node_id: str = "i=85") -> list[dict[str, Any]]:
        children = []
        for child in self._client.get_node(node_id).get_children():
            try:
                children.append({"node_id": str(child.nodeid), "browse_name": str(child.read_browse_name().Name), "node_class": str(child.read_node_class().name)})
            except Exception:  # noqa: BLE001 - one unreadable child must not fail the browse
                continue
        return children

    def write(self, node_id: str, value: Any) -> StatusCode:
        key = str(NodeId.parse(node_id))
        self.allowlist.check(key, value)
        try:
            self._client.get_node(key).write_value(value)
        except Exception:  # noqa: BLE001
            return StatusCode.BAD_NOT_WRITABLE
        return StatusCode.GOOD

    def describe(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "implementation": "asyncua",
            "real_server": True,
            "security_policy": self.security_string or "None -- an unencrypted, unauthenticated OPC UA session",
            "write_allowlist": self.allowlist.describe(),
        }


class OpcUaObserver:
    """A FASP adapter exposing an OPC UA subtree as observe capabilities.

    Declared at Layer 4 with `observe` interaction, so `LayerGuard` accepts
    it. There is deliberately no `write` capability here: writing is
    available through the client to *local* code with an allowlist, and is
    not something a network peer can reach by proposing an intent.
    """

    def __init__(self, client: OpcUaClient, *, nodes: dict[str, str] | None = None) -> None:
        self.client = client
        self.nodes = dict(nodes or {})

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {"id": "observe.opcua.read.v1", "risk": "observe", "max_runtime_s": 5, "layer": 4, "interaction": "observe", "network": "opc-ua"},
            {"id": "observe.opcua.browse.v1", "risk": "observe", "max_runtime_s": 5, "layer": 4, "interaction": "observe", "network": "opc-ua"},
        ]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        capability = intent.get("capability")
        parameters = intent.get("parameters") or {}
        if capability == "observe.opcua.read.v1":
            requested = parameters.get("names") or sorted(self.nodes)
            if not isinstance(requested, list) or len(requested) > 64:
                raise FaspError("schema.invalid", "observe.opcua.read.v1 accepts up to 64 declared names.")
            unknown = [name for name in requested if name not in self.nodes]
            if unknown:
                raise FaspError("auth.not_authorized", f"Names not published by this observer: {unknown[:5]}.")
            values = self.client.read([self.nodes[name] for name in requested])
            return {"status": "ok", "values": {name: value.to_dict() for name, value in zip(requested, values, strict=False)}}
        if capability == "observe.opcua.browse.v1":
            root = str(parameters.get("node_id", "ns=0;i=85"))
            return {"status": "ok", "children": self.client.browse(root)}
        raise FaspError("capability.unavailable", "This adapter exposes OPC UA observation only.")
