"""A fleet adapter configured by data, so most vendors need no new code.

Vendor fleet managers with an HTTP API differ in URLs, field names, and
authentication -- not in concepts. They all have a way to list vehicles,
read one, post a job, and cancel it. So this adapter takes an
`EndpointSpec` describing *where* and a `FieldMap` describing *what things
are called*, and integrates such a vendor with a configuration file instead
of a module.

That has a real security consequence, which is why the mapping language is
a set of dotted paths and not an expression language: a config file that
can only name fields cannot execute anything. There is no eval, no
template, no code path from configuration to execution -- the worst a bad
config can do is read the wrong field.

The HTTP client is injected. `urllib` works, and so does an `httpx` client
with the site's own mTLS material, retries, and proxy configuration
already set up, which is what a real deployment will want.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..protocol.errors import FaspError
from .model import Mission, MissionState, OperatingMode, Pose, StepKind, VehicleCapabilities, VehicleState

HttpCall = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def urllib_http(timeout_s: float = 10.0) -> HttpCall:
    """A minimal HTTP caller. Replace it with the site's own client."""

    def call(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        if not url.startswith(("http://", "https://")):
            raise FaspError("schema.invalid", "Fleet endpoint URLs must be http(s).")
        request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - scheme checked above
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise FaspError("transport.unreachable", f"Fleet manager is unreachable: {exc.__class__.__name__}.") from exc

    return call


def get_path(document: Any, path: str, default: Any = None) -> Any:
    """Read `a.b.0.c` out of nested JSON. The whole mapping language."""
    current = document
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return default
        if current is None:
            return default
    return current


@dataclass
class FieldMap:
    """Which vendor field means which neutral concept."""

    vehicle_list: str = "vehicles"
    vehicle_id: str = "id"
    online: str = "online"
    operating_mode: str = "mode"
    battery: str = "battery"
    battery_is_percent: bool = True
    position_x: str = "position.x"
    position_y: str = "position.y"
    position_theta: str = "position.theta"
    map_id: str = "position.map"
    charging: str = "charging"
    driving: str = "moving"
    paused: str = "paused"
    errors: str = "errors"
    current_mission: str = "current_job"
    estop: str = "safety.emergency_stop"
    protective_field: str = "safety.field_violated"
    mission_state: str = "status"
    mission_id: str = "id"
    mode_values: dict[str, str] = field(default_factory=lambda: {"auto": "AUTOMATIC", "automatic": "AUTOMATIC", "manual": "MANUAL", "service": "SERVICE", "teachin": "TEACHIN", "semi": "SEMIAUTOMATIC"})
    state_values: dict[str, str] = field(
        default_factory=lambda: {
            "queued": "ASSIGNED",
            "assigned": "ASSIGNED",
            "executing": "RUNNING",
            "running": "RUNNING",
            "paused": "PAUSED",
            "done": "COMPLETED",
            "completed": "COMPLETED",
            "failed": "FAILED",
            "error": "FAILED",
            "cancelled": "CANCELLED",
            "canceled": "CANCELLED",
        }
    )


@dataclass
class EndpointSpec:
    """Where the vendor's operations live."""

    base_url: str
    list_vehicles: str = "/vehicles"
    vehicle: str = "/vehicles/{vehicle_id}"
    dispatch: str = "/missions"
    cancel: str = "/missions/{mission_id}/cancel"
    mission: str = "/missions/{mission_id}"
    stop: str = "/vehicles/{vehicle_id}/stop"
    dispatch_method: str = "POST"
    cancel_method: str = "POST"
    stop_method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)

    def url(self, template: str, **values: str) -> str:
        return self.base_url.rstrip("/") + template.format(**values)


class RestFleetAdapter:
    """A `FleetManagerAdapter` driven entirely by `EndpointSpec` + `FieldMap`."""

    def __init__(
        self,
        fleet: str,
        endpoints: EndpointSpec,
        *,
        fields: FieldMap | None = None,
        http: HttpCall | None = None,
        vendor: str = "unknown",
        mission_body: Callable[[Mission, str], dict[str, Any]] | None = None,
    ) -> None:
        self.fleet = fleet
        self.endpoints = endpoints
        self.fields = fields or FieldMap()
        self.http = http or urllib_http()
        self.vendor = vendor
        # A vendor whose job body genuinely cannot be expressed by the
        # default shape supplies a builder. Still data-in/data-out: it
        # returns a dict, it does not get to perform the request.
        self.mission_body = mission_body or self._default_mission_body
        self._lock = threading.Lock()
        self._dispatched: dict[str, str] = {}

    # -- transport ---------------------------------------------------------
    def _request(self, method: str, url: str, body: dict[str, Any] | None = None) -> Any:
        headers = {"Accept": "application/json", **self.endpoints.headers}
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, raw = self.http(method, url, headers, payload)
        if status >= 400:
            raise FaspError("capability.unavailable", f"Fleet manager returned HTTP {status}.")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise FaspError("schema.invalid", "Fleet manager returned a non-JSON body.") from exc

    # -- mapping -----------------------------------------------------------
    def _to_state(self, document: Any) -> VehicleState:
        fields = self.fields
        raw_mode = str(get_path(document, fields.operating_mode, "AUTOMATIC")).strip().lower()
        try:
            mode = OperatingMode(fields.mode_values.get(raw_mode, raw_mode.upper()))
        except ValueError:
            mode = OperatingMode.SERVICE
        battery = get_path(document, fields.battery, 0)
        ratio = float(battery) / 100.0 if fields.battery_is_percent and isinstance(battery, (int, float)) else float(battery or 0)
        x, y = get_path(document, fields.position_x), get_path(document, fields.position_y)
        pose = Pose(float(x), float(y), float(get_path(document, fields.position_theta, 0.0) or 0.0), str(get_path(document, fields.map_id, "default"))) if isinstance(x, (int, float)) and isinstance(y, (int, float)) else None
        raw_errors = get_path(document, fields.errors, []) or []
        errors = tuple(
            {"code": str(item.get("code", item)) if isinstance(item, dict) else str(item), "level": str(item.get("level", "WARNING")).upper() if isinstance(item, dict) else "WARNING", "description": str(item.get("message", ""))[:200] if isinstance(item, dict) else ""}
            for item in (raw_errors if isinstance(raw_errors, list) else [raw_errors])
        )
        return VehicleState(
            vehicle_id=str(get_path(document, fields.vehicle_id, "")),
            fleet=self.fleet,
            online=bool(get_path(document, fields.online, True)),
            operating_mode=mode,
            pose=pose,
            battery_ratio=max(0.0, min(1.0, ratio)),
            charging=bool(get_path(document, fields.charging, False)),
            driving=bool(get_path(document, fields.driving, False)),
            paused=bool(get_path(document, fields.paused, False)),
            errors=errors,
            current_mission_id=str(get_path(document, fields.current_mission)) if get_path(document, fields.current_mission) else None,
            safety_estop_active=bool(get_path(document, fields.estop, False)),
            protective_field_violated=bool(get_path(document, fields.protective_field, False)),
            vendor_state=document if isinstance(document, dict) else {},
        )

    def _default_mission_body(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        return {
            "id": mission.mission_id,
            "vehicle_id": vehicle_id,
            "priority": mission.priority,
            "steps": [{"type": step.kind.value, "node": step.node_id, "pose": step.pose.to_dict() if step.pose else None, "parameters": step.parameters} for step in mission.steps],
        }

    # -- adapter interface ----------------------------------------------------
    def describe(self) -> dict[str, Any]:
        return {
            "vendor_interface": "generic REST",
            "vendor": self.vendor,
            "base_url": self.endpoints.base_url,
            "configured_by": "EndpointSpec + FieldMap (declarative; no expressions are evaluated)",
            "capabilities": ["dispatch", "cancel", "observe", "request_stop"],
            "not_provided": ["emergency stop", "trajectory control", "safety configuration"],
        }

    def list_vehicles(self) -> list[VehicleState]:
        document = self._request("GET", self.endpoints.url(self.endpoints.list_vehicles))
        listing = get_path(document, self.fields.vehicle_list, document if isinstance(document, list) else [])
        return [self._to_state(item) for item in (listing if isinstance(listing, list) else [])]

    def vehicle_state(self, vehicle_id: str) -> VehicleState:
        return self._to_state(self._request("GET", self.endpoints.url(self.endpoints.vehicle, vehicle_id=vehicle_id)))

    def capabilities(self, vehicle_id: str) -> VehicleCapabilities:
        del vehicle_id
        # Conservative until a vendor factsheet endpoint is configured: a
        # coordinator that assumes an unknown vehicle can do everything is
        # a coordinator that dispatches a pick to a tugger.
        return VehicleCapabilities(supported_steps=(StepKind.MOVE, StepKind.WAIT), vendor=self.vendor, interface="generic REST")

    def dispatch(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        response = self._request(self.endpoints.dispatch_method, self.endpoints.url(self.endpoints.dispatch), self.mission_body(mission, vehicle_id))
        with self._lock:
            self._dispatched[mission.mission_id] = vehicle_id
        return {"interface": "generic REST", "vendor_mission_id": get_path(response, self.fields.mission_id, mission.mission_id)}

    def cancel(self, mission_id: str) -> bool:
        try:
            self._request(self.endpoints.cancel_method, self.endpoints.url(self.endpoints.cancel, mission_id=mission_id), {})
        except FaspError:
            return False
        return True

    def mission_state(self, mission_id: str) -> MissionState:
        document = self._request("GET", self.endpoints.url(self.endpoints.mission, mission_id=mission_id))
        raw = str(get_path(document, self.fields.mission_state, "RUNNING")).strip().lower()
        try:
            return MissionState(self.fields.state_values.get(raw, raw.upper()))
        except ValueError:
            return MissionState.RUNNING

    def request_stop(self, vehicle_id: str, reason: str) -> bool:
        try:
            self._request(self.endpoints.stop_method, self.endpoints.url(self.endpoints.stop, vehicle_id=vehicle_id), {"reason": str(reason)[:120]})
        except FaspError:
            return False
        return True
