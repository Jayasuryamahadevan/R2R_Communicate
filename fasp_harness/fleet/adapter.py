"""The one interface a vendor integration implements, and the multiplexer.

`FleetManagerAdapter` is intentionally small. Everything a scheduler needs
is here; nothing a scheduler should not do is. In particular there is no
`send_path`, no `set_velocity`, and no `clear_safety` -- an adapter cannot
offer those because the interface has no place to put them.

`FleetRegistry` is what makes "multi-vendor" real rather than aspirational.
Vehicles are addressed as `fleet:vehicle_id`, so two vendors that both call
a robot `AGV-01` do not collide, and the scheduler above never branches on
vendor. A vendor whose manager is down degrades to *that fleet* being
unavailable, not to an exception escaping into the scheduler: adapter calls
are wrapped, and a failing adapter is reported as unhealthy while every
other fleet keeps working.
"""

from __future__ import annotations

import threading
from typing import Any, Protocol, runtime_checkable

from ..protocol.errors import FaspError
from ..timestamps import stamp
from .model import Mission, MissionState, VehicleCapabilities, VehicleState


@runtime_checkable
class FleetManagerAdapter(Protocol):
    """One vendor's fleet manager, normalised."""

    fleet: str

    def describe(self) -> dict[str, Any]:
        """Vendor, interface, version, and what this adapter can actually do."""
        ...

    def list_vehicles(self) -> list[VehicleState]: ...

    def vehicle_state(self, vehicle_id: str) -> VehicleState: ...

    def capabilities(self, vehicle_id: str) -> VehicleCapabilities: ...

    def dispatch(self, mission: Mission, vehicle_id: str) -> dict[str, Any]:
        """Hand a goal-level mission to a vehicle. Returns vendor detail."""
        ...

    def cancel(self, mission_id: str) -> bool: ...

    def mission_state(self, mission_id: str) -> MissionState: ...

    def request_stop(self, vehicle_id: str, reason: str) -> bool:
        """Ask the vehicle to stop. A *request* at Layer 2/3 -- the
        vehicle's own certified protective stop is unaffected by whether
        this succeeds, which is exactly why it is allowed to be best
        effort."""
        ...


class FleetError(FaspError):
    def __init__(self, detail: str, *, code: str = "capability.unavailable") -> None:
        super().__init__(code, detail)


class FleetRegistry:
    """Several vendors' fleets behind one address space."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._adapters: dict[str, FleetManagerAdapter] = {}
        self._health: dict[str, dict[str, Any]] = {}

    # -- membership -------------------------------------------------------
    def register(self, adapter: FleetManagerAdapter) -> FleetManagerAdapter:
        fleet = getattr(adapter, "fleet", "")
        if not isinstance(fleet, str) or not fleet or ":" in fleet:
            raise FaspError("schema.invalid", "A fleet adapter needs a non-empty `fleet` name without a colon.")
        with self._lock:
            self._adapters[fleet] = adapter
            self._health[fleet] = {"fleet": fleet, "healthy": True, "detail": "registered", "checked_at": stamp()}
        return adapter

    def unregister(self, fleet: str) -> None:
        with self._lock:
            self._adapters.pop(fleet, None)
            self._health.pop(fleet, None)

    @property
    def fleets(self) -> list[str]:
        with self._lock:
            return sorted(self._adapters)

    def adapter(self, fleet: str) -> FleetManagerAdapter:
        with self._lock:
            adapter = self._adapters.get(fleet)
        if adapter is None:
            raise FleetError(f"No fleet adapter is registered for {fleet!r}.")
        return adapter

    # -- addressing --------------------------------------------------------
    @staticmethod
    def split(address: str) -> tuple[str, str]:
        """`fleet:vehicle` -> (fleet, vehicle)."""
        fleet, separator, vehicle = str(address).partition(":")
        if not separator or not fleet or not vehicle:
            raise FaspError("schema.invalid", "A vehicle address must be 'fleet:vehicle_id'.")
        return fleet, vehicle

    @staticmethod
    def address(fleet: str, vehicle_id: str) -> str:
        return f"{fleet}:{vehicle_id}"

    # -- fan-out ------------------------------------------------------------
    def _guarded(self, fleet: str, operation: str, call: Any) -> Any:
        """Run one adapter call, recording that fleet's health either way.

        A vendor manager that is unreachable must degrade to "that fleet is
        unavailable", never to an exception escaping into the scheduler and
        taking every other fleet's work with it.
        """
        try:
            result = call()
        except FaspError as error:
            with self._lock:
                self._health[fleet] = {"fleet": fleet, "healthy": False, "detail": f"{operation}: {error.detail}", "checked_at": stamp()}
            raise
        except Exception as exc:  # noqa: BLE001 - vendor SDKs raise anything
            with self._lock:
                self._health[fleet] = {"fleet": fleet, "healthy": False, "detail": f"{operation}: {exc.__class__.__name__}", "checked_at": stamp()}
            raise FleetError(f"Fleet {fleet!r} failed during {operation}.", code="transport.unreachable") from exc
        with self._lock:
            self._health[fleet] = {"fleet": fleet, "healthy": True, "detail": operation, "checked_at": stamp()}
        return result

    def list_vehicles(self, *, fleet: str | None = None) -> list[tuple[str, VehicleState]]:
        """Every vehicle, addressed. An unreachable fleet contributes nothing
        rather than failing the whole listing."""
        results: list[tuple[str, VehicleState]] = []
        for name in ([fleet] if fleet else self.fleets):
            adapter = self.adapter(name)
            try:
                states = self._guarded(name, "list_vehicles", adapter.list_vehicles)
            except FaspError:
                continue
            results.extend((self.address(name, state.vehicle_id), state) for state in states)
        return results

    def vehicle_state(self, address: str) -> VehicleState:
        fleet, vehicle_id = self.split(address)
        return self._guarded(fleet, "vehicle_state", lambda: self.adapter(fleet).vehicle_state(vehicle_id))

    def capabilities(self, address: str) -> VehicleCapabilities:
        fleet, vehicle_id = self.split(address)
        return self._guarded(fleet, "capabilities", lambda: self.adapter(fleet).capabilities(vehicle_id))

    def dispatch(self, mission: Mission, address: str) -> dict[str, Any]:
        fleet, vehicle_id = self.split(address)
        return self._guarded(fleet, "dispatch", lambda: self.adapter(fleet).dispatch(mission, vehicle_id))

    def cancel(self, fleet: str, mission_id: str) -> bool:
        return bool(self._guarded(fleet, "cancel", lambda: self.adapter(fleet).cancel(mission_id)))

    def mission_state(self, fleet: str, mission_id: str) -> MissionState:
        return self._guarded(fleet, "mission_state", lambda: self.adapter(fleet).mission_state(mission_id))

    def request_stop(self, address: str, reason: str) -> bool:
        """Best effort, and never allowed to raise: a halt request that
        throws is worse than one that returns False, because the caller is
        usually already handling something going wrong."""
        try:
            fleet, vehicle_id = self.split(address)
            return bool(self._guarded(fleet, "request_stop", lambda: self.adapter(fleet).request_stop(vehicle_id, reason)))
        except Exception:  # noqa: BLE001 - see docstring
            return False

    def request_stop_all(self, reason: str) -> dict[str, bool]:
        """Fleet-wide stop request. Attempts every vehicle even if some fail."""
        outcomes: dict[str, bool] = {}
        for address, _state in self.list_vehicles():
            outcomes[address] = self.request_stop(address, reason)
        return outcomes

    # -- selection -----------------------------------------------------------
    def select_vehicle(self, mission: Mission, *, minimum_battery: float = 0.15) -> tuple[str | None, list[dict[str, Any]]]:
        """Pick a vehicle for a mission, and explain every rejection.

        The explanation is the useful part: "no vehicle available" is the
        least actionable message a fleet system can produce, and the reasons
        are already computed here.
        """
        considered: list[dict[str, Any]] = []
        best: tuple[float, str] | None = None
        for address, state in self.list_vehicles(fleet=mission.fleet):
            if mission.vehicle_id and state.vehicle_id != mission.vehicle_id and address != mission.vehicle_id:
                continue
            ok, reason = state.dispatchable(minimum_battery=minimum_battery)
            if ok:
                try:
                    supports, reason = self.capabilities(address).supports(mission)
                except FaspError as error:
                    supports, reason = False, error.detail
                ok = supports
            considered.append({"vehicle": address, "eligible": ok, "reason": reason})
            if not ok:
                continue
            # Prefer the most charged eligible vehicle. A distance-based
            # score belongs here too once a site map is configured; battery
            # is the tiebreaker that is always available and never wrong.
            score = state.battery_ratio
            if best is None or score > best[0]:
                best = (score, address)
        return (best[1] if best else None), considered

    # -- health ---------------------------------------------------------------
    def health(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._health[fleet] for fleet in sorted(self._health)]

    def describe(self) -> list[dict[str, Any]]:
        described: list[dict[str, Any]] = []
        for fleet in self.fleets:
            try:
                described.append({"fleet": fleet, **self.adapter(fleet).describe()})
            except Exception as exc:  # noqa: BLE001 - a broken describe() must not hide the rest
                described.append({"fleet": fleet, "error": exc.__class__.__name__})
        return described
