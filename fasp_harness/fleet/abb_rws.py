"""Pilot adapter for an ABB GoFa through OmniCore Robot Web Services.

The adapter deliberately does not turn Robot Web Services into a remote motion
API.  An authorised ABB programmer installs a small RAPID mailbox loop and
teaches the only routines that loop accepts.  FASP may then commit one locally
allow-listed command by writing its data first and a monotonically increasing
sequence number last.

Writes target RobotWare 7 / RWS 2.0, which refuses a RAPID symbol write from a
client holding no mastership.  One block of writes takes RAPID Edit mastership
once and releases it again, which is also what stops another RWS client
interleaving a write between the payload and the commit.

No endpoint for motor power, jogging, joint targets, program upload, safety I/O,
or controller configuration exists in this module.  Cancellation is a
cooperative request to RAPID, never an emergency-stop claim.
"""

from __future__ import annotations

import http.cookiejar
import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

from ..protocol.errors import FaspError
from .model import Mission, MissionState, OperatingMode, StepKind, VehicleCapabilities, VehicleState

RwsHttp = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]

_RAPID_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
_WIRE_TEXT = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_COMMAND = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class AbbRwsPilotConfig:
    """Local commissioning policy for one controller.

    ``commanding_enabled`` and ``allowed_commands`` are local configuration,
    not values a network mission can change.  Commanding also requires an
    expected controller name, preventing a copied configuration from driving a
    different controller at the same address.
    """

    base_url: str
    username: str
    password: str = field(repr=False)
    vehicle_id: str = "gofa"
    expected_controller_name: str | None = None
    task: str = "T_ROB1"
    module: str = "FASP_Pilot"
    mechunit: str = "ROB_1"
    commanding_enabled: bool = False
    allowed_commands: frozenset[str] = frozenset()
    allow_insecure_http: bool = False
    timeout_s: float = 5.0

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise FaspError("schema.invalid", "ABB RWS base_url must be an absolute HTTP(S) URL.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise FaspError("schema.invalid", "ABB RWS base_url must not contain credentials, a query, or a fragment.")
        if not self.username or not self.password:
            raise FaspError("auth.not_authorized", "ABB RWS requires a non-empty least-privilege username and password.")
        if parsed.scheme != "https" and not self.allow_insecure_http:
            raise FaspError("auth.not_authorized", "ABB RWS requires HTTPS unless insecure HTTP is explicitly enabled for an isolated lab.")
        if self.commanding_enabled and not self.expected_controller_name:
            raise FaspError("schema.invalid", "Commanding requires expected_controller_name to pin the pilot to one controller.")
        if not 0.1 <= self.timeout_s <= 60.0:
            raise FaspError("schema.invalid", "ABB RWS timeout_s must be between 0.1 and 60 seconds.")
        for label, value in (("task", self.task), ("module", self.module), ("mechunit", self.mechunit)):
            if not _RAPID_IDENTIFIER.fullmatch(value):
                raise FaspError("schema.invalid", f"ABB {label} is not a valid RAPID identifier.")
        if not _WIRE_TEXT.fullmatch(self.vehicle_id):
            raise FaspError("schema.invalid", "ABB vehicle_id contains unsupported characters.")
        for command in self.allowed_commands:
            if not _COMMAND.fullmatch(command):
                raise FaspError("schema.invalid", f"ABB command {command!r} is not a safe mailbox command identifier.")


def urllib_rws_http(config: AbbRwsPilotConfig, *, ssl_context: ssl.SSLContext | None = None) -> RwsHttp:
    """Create a stateful Digest/Basic authenticated RWS transport.

    RWS 1.0 challenges with Digest and RWS 2.0 with Basic, so both handlers are
    registered and the controller's own challenge selects one.  The cookie processor
    keeps the controller session stable; its mastership and subscription limits
    are session-scoped.  TLS verification stays enabled unless the caller
    deliberately supplies a different SSL context.
    """

    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, config.base_url.rstrip("/"), config.username, config.password)
    handlers: list[Any] = [
        urllib.request.HTTPDigestAuthHandler(password_manager),
        urllib.request.HTTPBasicAuthHandler(password_manager),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    ]
    if urllib.parse.urlsplit(config.base_url).scheme == "https":
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context or ssl.create_default_context()))
    opener = urllib.request.build_opener(*handlers)

    def call(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        if not url.startswith(config.base_url.rstrip("/") + "/"):
            raise FaspError("auth.not_authorized", "ABB RWS transport refused a request outside its configured controller.")
        request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - origin is pinned above
        try:
            with opener.open(request, timeout=config.timeout_s) as response:  # noqa: S310 - origin is pinned above
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise FaspError("transport.unreachable", f"ABB controller is unreachable: {exc.__class__.__name__}.") from exc

    return call


def parse_rws_xhtml(raw: bytes) -> dict[str, str]:
    """Flatten ABB's XHTML ``span`` resources into their named values."""

    if not raw:
        return {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise FaspError("schema.invalid", "ABB RWS returned malformed XHTML.") from exc
    values: dict[str, str] = {}
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "span":
            continue
        name = element.attrib.get("class")
        if name:
            values[name] = "".join(element.itertext()).strip()
    return values


def _rapid_string(value: str) -> str:
    if not _WIRE_TEXT.fullmatch(value):
        raise FaspError("schema.invalid", "ABB mailbox strings may contain only letters, digits, dot, underscore, colon, and hyphen.")
    return f'"{value}"'


def _unquote_rapid(value: str) -> str:
    text = value.strip()
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else text


_RESULT_STATES = {
    "IDLE": MissionState.ACCEPTED,
    "QUEUED": MissionState.ASSIGNED,
    "RUNNING": MissionState.RUNNING,
    "COMPLETED": MissionState.COMPLETED,
    "FAILED": MissionState.FAILED,
    "REJECTED": MissionState.REJECTED,
    "CANCELLED": MissionState.CANCELLED,
}


class AbbRwsPilotAdapter:
    """One ABB GoFa/OmniCore controller behind the fleet adapter contract."""

    _SYMBOLS = {
        "protocol": "fasp_protocol_version",
        "command_seq": "fasp_command_seq",
        "ack_seq": "fasp_ack_seq",
        "mission_id": "fasp_mission_id",
        "command": "fasp_command",
        "result": "fasp_result",
        "detail": "fasp_detail",
        "cancel": "fasp_cancel_requested",
    }

    def __init__(self, fleet: str, config: AbbRwsPilotConfig, *, http: RwsHttp | None = None) -> None:
        if not fleet or ":" in fleet:
            raise FaspError("schema.invalid", "ABB fleet name must be non-empty and contain no colon.")
        self.fleet = fleet
        self.config = config
        self.http = http or urllib_rws_http(config)
        self._lock = threading.RLock()
        self._identity: dict[str, str] | None = None
        self._states: dict[str, MissionState] = {}

    @property
    def _base(self) -> str:
        return self.config.base_url.rstrip("/")

    def _request(self, method: str, path: str, form: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Accept": "application/xhtml+xml;v=2.0"}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded;v=2.0"
        status, raw = self.http(method, self._base + path, headers, body)
        if status >= 400:
            # Controller error bodies can contain deployment details; keep the
            # cross-system error intentionally small and credential-free.
            code = "auth.not_authorized" if status in {401, 403} else "capability.unavailable"
            raise FaspError(code, f"ABB RWS returned HTTP {status} for {path.split('?', 1)[0]}.")
        return parse_rws_xhtml(raw)

    def _symbol_path(self, name: str) -> str:
        # RWS 2.0 shape: the symbol sits inside the URL and the resource is
        # `/data`.  RobotWare 7 removed the RWS 1.0 `/symbol/data/<sym>?action=set`
        # form entirely, so the older spelling 404s rather than degrading.
        symbol = self._SYMBOLS[name]
        return f"/rw/rapid/symbol/RAPID/{self.config.task}/{self.config.module}/{symbol}/data"

    def _read_symbol(self, name: str) -> str:
        return _unquote_rapid(self._request("GET", self._symbol_path(name)).get("value", ""))

    def _set_symbol(self, name: str, rapid_value: str) -> None:
        self._request("POST", self._symbol_path(name), {"value": rapid_value})

    @contextmanager
    def _edit_mastership(self) -> Iterator[None]:
        """Hold RAPID Edit mastership for exactly one block of writes.

        RWS 2.0 defaults its `mastership` parameter to `explicit`, so a symbol
        write from a client holding nothing is refused.  Taking it once around
        the whole block rather than per call is deliberate: it is what stops a
        second RWS client writing between the payload and the commit sequence.

        Mastership left held is mastership the FlexPendant cannot take back, so
        release runs on both paths -- and on the failing path a release error is
        suppressed rather than replacing the failure that caused it.
        """

        self._request("POST", "/rw/mastership/edit/request", {})
        try:
            yield
        except BaseException:
            with suppress(FaspError):
                self._request("POST", "/rw/mastership/edit/release", {})
            raise
        self._request("POST", "/rw/mastership/edit/release", {})

    def _controller_identity(self) -> dict[str, str]:
        if self._identity is None:
            self._identity = self._request("GET", "/ctrl/identity")
        return dict(self._identity)

    def _verify_controller_pin(self) -> str:
        name = self._controller_identity().get("ctrl-name", "")
        expected = self.config.expected_controller_name
        if expected and name != expected:
            raise FaspError("auth.not_authorized", f"ABB controller identity {name!r} does not match the locally pinned name {expected!r}.")
        return name

    def _operation_mode(self) -> tuple[OperatingMode, str]:
        raw = self._request("GET", "/rw/panel/opmode").get("opmode", "UNDEF").upper()
        mapped = OperatingMode.AUTOMATIC if raw == "AUTO" else OperatingMode.MANUAL if raw in {"MANR", "MANF"} else OperatingMode.SERVICE
        return mapped, raw

    def _controller_state(self) -> str:
        # RWS 2.0 hyphenates the path; the field inside it did not change.
        values = self._request("GET", "/rw/panel/ctrl-state")
        return values.get("ctrlstate", values.get("ctrl-state", "unknown")).lower()

    def _execution_state(self) -> str:
        return self._request("GET", "/rw/rapid/execution").get("ctrlexecstate", "unknown").lower()

    def _tcp_target(self) -> dict[str, float] | None:
        path = f"/rw/motionsystem/mechunits/{self.config.mechunit}/robtarget?coordinate=Base"
        values = self._request("GET", path)
        try:
            return {name: float(values[name]) for name in ("x", "y", "z", "q1", "q2", "q3", "q4")}
        except (KeyError, ValueError):
            return None

    def describe(self) -> dict[str, Any]:
        return {
            "vendor": "ABB",
            "vendor_interface": "Robot Web Services 2.0 + preloaded RAPID mailbox",
            "controller": self.config.expected_controller_name or "not pinned (observation only)",
            "commanding_enabled": self.config.commanding_enabled,
            "allowed_commands": sorted(self.config.allowed_commands),
            "capabilities": ["observe"] + (["dispatch allow-listed RAPID mailbox command", "cooperative cancel"] if self.config.commanding_enabled else []),
            "not_provided": ["motor power", "jogging", "joint or Cartesian motion targets", "program upload", "safety I/O", "safety reset", "mobile-base control"],
        }

    def pilot_preflight(self) -> dict[str, Any]:
        """Read-only commissioning evidence for the ABB pilot mailbox.

        This intentionally reports controller readiness, not safety approval.
        Safety functions remain local to the assessed robot/mobile-base cell and
        are not inferable from ordinary RWS state reads.
        """

        with self._lock:
            checks: list[dict[str, Any]] = []
            try:
                identity = self._controller_identity()
                controller_name = identity.get("ctrl-name", "")
                pinned = bool(self.config.expected_controller_name) and controller_name == self.config.expected_controller_name
                checks.append({"name": "controller_identity", "ok": pinned, "detail": controller_name or "controller returned no name"})

                mode, raw_mode = self._operation_mode()
                checks.append({"name": "operation_mode", "ok": mode is OperatingMode.AUTOMATIC, "detail": raw_mode})
                controller_state = self._controller_state()
                checks.append({"name": "motors_already_on", "ok": controller_state == "motoron", "detail": controller_state})
                execution = self._execution_state()
                checks.append({"name": "rapid_mailbox_running", "ok": execution == "running", "detail": execution})
                protocol = self._read_symbol("protocol")
                checks.append({"name": "mailbox_protocol", "ok": protocol == "1", "detail": protocol or "missing"})
                command_seq = int(float(self._read_symbol("command_seq") or "0"))
                ack_seq = int(float(self._read_symbol("ack_seq") or "0"))
                result = self._read_symbol("result").upper() or "UNKNOWN"
                mission_id = self._read_symbol("mission_id") or "none"
                command = self._read_symbol("command") or "none"
                synced = command_seq == ack_seq
                checks.append({"name": "mailbox_sequence", "ok": synced, "detail": f"command={command_seq}, ack={ack_seq}"})
                terminal_or_idle = result in {"IDLE", "COMPLETED", "FAILED", "REJECTED", "CANCELLED"}
                checks.append({"name": "mailbox_available", "ok": synced and terminal_or_idle, "detail": f"result={result}, mission={mission_id}, command={command}"})
            except FaspError as error:
                checks.append({"name": "rws_reachable", "ok": False, "detail": f"{error.code}: {error.detail}"})
                return {
                    "fleet": self.fleet,
                    "vehicle_id": self.config.vehicle_id,
                    "observation_ready": False,
                    "ready_for_noop": False,
                    "commanding_enabled": self.config.commanding_enabled,
                    "checks": checks,
                    "safety_claim": "No safety approval is inferred from RWS; local certified safety remains authoritative.",
                }

        observation_ready = all(check["ok"] for check in checks if check["name"] in {"controller_identity", "mailbox_protocol", "mailbox_sequence"})
        ready_for_noop = observation_ready and self.config.commanding_enabled and all(
            check["ok"] for check in checks if check["name"] in {"operation_mode", "motors_already_on", "rapid_mailbox_running", "mailbox_available"}
        )
        return {
            "fleet": self.fleet,
            "vehicle_id": self.config.vehicle_id,
            "controller_name": controller_name,
            "controller_type": identity.get("ctrl-type", ""),
            "operation_mode": raw_mode,
            "controller_state": controller_state,
            "rapid_execution": execution,
            "mailbox": {"protocol": protocol, "command_seq": command_seq, "ack_seq": ack_seq, "result": result, "mission_id": mission_id, "command": command},
            "observation_ready": observation_ready,
            "ready_for_noop": ready_for_noop,
            "commanding_enabled": self.config.commanding_enabled,
            "allowed_commands": sorted(self.config.allowed_commands),
            "checks": checks,
            "safety_claim": "No safety approval is inferred from RWS; local certified safety remains authoritative.",
        }

    def pilot_health(self) -> tuple[bool, str]:
        """A readiness probe for deployments that configured this adapter."""

        report = self.pilot_preflight()
        failed = [item["name"] for item in report["checks"] if not item["ok"]]
        return bool(report["observation_ready"]), "ready" if report["observation_ready"] else f"failed checks: {', '.join(failed)}"

    def list_vehicles(self) -> list[VehicleState]:
        return [self.vehicle_state(self.config.vehicle_id)]

    def vehicle_state(self, vehicle_id: str) -> VehicleState:
        if vehicle_id != self.config.vehicle_id:
            raise FaspError("schema.invalid", f"Unknown ABB pilot vehicle {vehicle_id!r}.")
        identity = self._controller_identity()
        mode, raw_mode = self._operation_mode()
        controller_state = self._controller_state()
        execution = self._execution_state()
        result = self._read_symbol("result").upper() or "UNKNOWN"
        mission_id = self._read_symbol("mission_id") or None
        cancel_requested = self._read_symbol("cancel").upper() == "TRUE"
        tcp_target = self._tcp_target()
        active = result in {"QUEUED", "RUNNING"}
        errors: list[dict[str, Any]] = []
        if execution != "running":
            errors.append({"code": "rapid_not_running", "level": "FATAL", "description": "The preloaded RAPID mailbox task is not running."})
        if controller_state != "motoron":
            errors.append({"code": "motors_not_on", "level": "FATAL", "description": "The ABB controller does not report motors on."})
        return VehicleState(
            vehicle_id=vehicle_id,
            fleet=self.fleet,
            online=True,
            operating_mode=mode,
            # The RWS robtarget is the arm TCP in its base coordinate system,
            # not the LiDAR mobile-base pose.  Treating it as a map pose would
            # corrupt spatial coordination, so it remains vendor telemetry.
            pose=None,
            battery_ratio=1.0,
            charging=False,
            driving=result == "RUNNING",
            paused=cancel_requested,
            errors=tuple(errors),
            current_mission_id=mission_id if active else None,
            vendor_state={
                "controller_name": identity.get("ctrl-name", ""),
                "controller_type": identity.get("ctrl-type", ""),
                "operation_mode": raw_mode,
                "controller_state": controller_state,
                "rapid_execution": execution,
                "mailbox_result": result,
                "cancel_requested": cancel_requested,
                "tcp_robtarget_base_mm": tcp_target,
                "safety_state_source": "ABB controller; FASP does not write or reset safety functions",
            },
        )

    def capabilities(self, vehicle_id: str) -> VehicleCapabilities:
        if vehicle_id != self.config.vehicle_id:
            raise FaspError("schema.invalid", f"Unknown ABB pilot vehicle {vehicle_id!r}.")
        return VehicleCapabilities(
            max_speed_mps=0.0,
            payload_kg=0.0,
            supported_steps=(StepKind.CUSTOM,),
            vendor="ABB",
            model="GoFa CRB 15000 pilot",
            interface="RWS 2.0 / RAPID mailbox",
        )

    def _require_commandable(self) -> None:
        if not self.config.commanding_enabled:
            raise FaspError("auth.not_authorized", "ABB pilot is observation-only; commanding is disabled in local configuration.")
        self._verify_controller_pin()
        mode, raw_mode = self._operation_mode()
        if mode is not OperatingMode.AUTOMATIC:
            raise FaspError("capability.unavailable", f"ABB controller must be in AUTO for pilot dispatch, not {raw_mode}.")
        if self._controller_state() != "motoron":
            raise FaspError("capability.unavailable", "ABB controller must already report motors on; FASP never turns motors on.")
        if self._execution_state() != "running":
            raise FaspError("capability.unavailable", "The authorised operator must start the RAPID mailbox task locally before dispatch.")
        if self._read_symbol("protocol") != "1":
            raise FaspError("capability.unavailable", "ABB RAPID mailbox protocol version is missing or unsupported.")

    def dispatch(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        if vehicle_id != self.config.vehicle_id:
            raise FaspError("schema.invalid", f"Unknown ABB pilot vehicle {vehicle_id!r}.")
        if len(mission.steps) != 1 or mission.steps[0].kind is not StepKind.CUSTOM:
            raise FaspError("schema.invalid", "An ABB pilot mission must contain exactly one custom mailbox command.")
        command = str(mission.steps[0].parameters.get("command", ""))
        if command not in self.config.allowed_commands:
            raise FaspError("auth.not_authorized", f"ABB command {command!r} is not on the local pilot allowlist.")
        if not _COMMAND.fullmatch(command) or not _WIRE_TEXT.fullmatch(mission.mission_id):
            raise FaspError("schema.invalid", "ABB pilot command or mission_id contains unsupported characters.")

        with self._lock:
            self._require_commandable()
            current_mission = self._read_symbol("mission_id")
            current_command = self._read_symbol("command")
            current_result = self._read_symbol("result").upper()
            command_seq = int(float(self._read_symbol("command_seq") or "0"))
            ack_seq = int(float(self._read_symbol("ack_seq") or "0"))

            if current_mission == mission.mission_id:
                if current_command != command:
                    raise FaspError("conflict", "The ABB controller already knows this mission_id with a different command.")
                # If the commit write succeeded (seq > ack), or RAPID already
                # produced a terminal result, this is a true idempotent retry.
                # With seq == ack and a non-terminal result, an earlier RWS
                # request failed before the commit; safely rewrite the mailbox
                # and commit it below instead of stranding the mission forever.
                state = _RESULT_STATES.get(current_result)
                if command_seq != ack_seq or state is not None and state.terminal:
                    resolved = state or MissionState.RUNNING
                    self._states[mission.mission_id] = resolved
                    return {"interface": "ABB RWS mailbox v1", "vendor_mission_id": mission.mission_id, "sequence": command_seq, "idempotent": True}
            if command_seq != ack_seq or current_result in {"QUEUED", "RUNNING"}:
                if current_mission != mission.mission_id:
                    raise FaspError("capability.unavailable", f"ABB controller is busy with mission {current_mission or 'unknown'}.")

            next_seq = max(command_seq, ack_seq) + 1
            # Transaction by ordering: the RAPID loop watches command_seq, so
            # no partial set of earlier writes can execute.  Commit is last.
            with self._edit_mastership():
                self._set_symbol("mission_id", _rapid_string(mission.mission_id))
                self._set_symbol("command", _rapid_string(command))
                self._set_symbol("detail", _rapid_string("queued"))
                self._set_symbol("result", _rapid_string("QUEUED"))
                self._set_symbol("cancel", "FALSE")
                self._set_symbol("command_seq", str(next_seq))
            self._states[mission.mission_id] = MissionState.ASSIGNED
            return {"interface": "ABB RWS mailbox v1", "vendor_mission_id": mission.mission_id, "sequence": next_seq, "idempotent": False}

    def mission_state(self, mission_id: str) -> MissionState:
        with self._lock:
            current_mission = self._read_symbol("mission_id")
            if current_mission == mission_id:
                result = self._read_symbol("result").upper()
                state = _RESULT_STATES.get(result, MissionState.RUNNING)
                self._states[mission_id] = state
                return state
            if mission_id in self._states:
                return self._states[mission_id]
        raise FaspError("schema.invalid", f"Unknown ABB pilot mission {mission_id!r}.")

    def cancel(self, mission_id: str) -> bool:
        with self._lock:
            try:
                self._require_commandable()
                if self._read_symbol("mission_id") != mission_id:
                    return False
                with self._edit_mastership():
                    self._set_symbol("cancel", "TRUE")
                return True
            except FaspError:
                return False

    def request_stop(self, vehicle_id: str, reason: str) -> bool:
        del reason  # Never sent to or interpreted by the controller.
        if vehicle_id != self.config.vehicle_id:
            return False
        with self._lock:
            try:
                self._require_commandable()
                with self._edit_mastership():
                    self._set_symbol("cancel", "TRUE")
                return True
            except FaspError:
                return False
