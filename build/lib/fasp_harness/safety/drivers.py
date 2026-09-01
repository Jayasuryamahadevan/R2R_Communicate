"""How a coordinator observes a safety controller it does not control.

`SafetyControllerDriver` is the whole vendor boundary: everything above it
(`SafetySupervisor`, the safety case, the HIL bench) is written against
this interface, so integrating a Pilz PNOZmulti, a Sick Flexi Soft, a
Siemens F-CPU, or a bare safety relay with an auxiliary contact is a new
driver and nothing else.

Two drivers ship. `ModbusSafetyController` talks to real hardware over
Modbus/TCP. `SimulatedSafetyController` is a deterministic model with the
same interface, used by tests, by the offline HIL bench, and as the twin's
Layer 1 stand-in -- it is a test double, and it says so in `describe()` so
a deployment report can never mistake it for a certified device.

The interface has a deliberate asymmetry: `read_status()` and
`request_stop()` exist; there is no `clear()`, no `reset()`, no
`mute_zone()`. Restoring a safety function after a demand is local,
physical, and often standards-mandated to require a deliberate manual
action at the machine. A driver that offered it over this interface would
be handing a network peer the one authority FASP must never have.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..industrial.modbus import ModbusError, ModbusTcpClient, SafetyRegisterMap, SignalMapping
from ..protocol.errors import FaspError
from ..timestamps import stamp


@dataclass(frozen=True)
class SafetyStatus:
    """One sample of a safety controller's state.

    `stale` and `reachable` are first-class rather than implied: a
    coordinator that cannot see the safety controller must behave as though
    the news is bad, and that is only possible if "no news" is representable.
    """

    reachable: bool
    estop_clear: bool
    protective_stop_clear: bool
    guards_closed: bool
    reset_required: bool
    signals: dict[str, bool] = field(default_factory=dict)
    device: str = "unknown"
    sampled_at: str = ""
    age_ms: float = 0.0
    stale: bool = False
    detail: str = ""

    @property
    def safe_to_move(self) -> bool:
        """True only when every channel positively says so.

        Note the `reachable` and `stale` terms: an unknown state is an
        unsafe state. This is the one place in the codebase where a
        default matters more than the logic around it.
        """
        return bool(self.reachable and not self.stale and self.estop_clear and self.protective_stop_clear and self.guards_closed and not self.reset_required)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "safe_to_move": self.safe_to_move}

    @classmethod
    def unreachable(cls, device: str, detail: str) -> SafetyStatus:
        """The fail-safe sample: everything unsafe, because nothing is known."""
        return cls(
            reachable=False,
            estop_clear=False,
            protective_stop_clear=False,
            guards_closed=False,
            reset_required=True,
            device=device,
            sampled_at=stamp(),
            stale=True,
            detail=detail,
        )


@runtime_checkable
class SafetyControllerDriver(Protocol):
    """Read Layer 1 state; ask Layer 1 to stop. Never anything else."""

    def read_status(self) -> SafetyStatus: ...

    def request_stop(self, reason: str) -> bool:
        """Ask the controller for a protective stop. Returns whether the
        request was *delivered*, never whether the machine has stopped --
        only the controller's own status can say that."""
        ...

    def describe(self) -> dict[str, Any]:
        """Vendor, model, integrity claim, and whether this is real hardware."""
        ...


class SimulatedSafetyController:
    """A deterministic safety controller for tests, CI, and offline HIL.

    Models the parts that matter to a supervisor: independent channels, a
    latched stop that survives the demand going away, a mandatory manual
    reset, and a configurable actuation delay so a bench can measure a
    response time that is not zero.
    """

    IS_REAL_HARDWARE = False

    def __init__(self, *, device: str = "simulated-safety-plc", stop_delay_s: float = 0.0) -> None:
        self.device = device
        self.stop_delay_s = stop_delay_s
        self._lock = threading.Lock()
        self._estop_pressed = False
        self._zone_violated = False
        self._guard_open = False
        self._latched = False
        self._reset_required = False
        self._stop_requests: list[dict[str, Any]] = []
        self._unreachable = False

    # -- physical stimuli (a bench or a test drives these) ------------
    def press_estop(self) -> None:
        with self._lock:
            self._estop_pressed = True
            self._latched = True
            self._reset_required = True

    def release_estop(self) -> None:
        """Release the button. The stop stays latched: releasing an E-stop
        is not the same as resetting the machine, and conflating the two is
        a classic and dangerous integration bug."""
        with self._lock:
            self._estop_pressed = False

    def set_zone_violated(self, violated: bool) -> None:
        with self._lock:
            self._zone_violated = violated
            if violated:
                self._latched = True
                self._reset_required = True

    def set_guard_open(self, is_open: bool) -> None:
        with self._lock:
            self._guard_open = is_open
            if is_open:
                self._latched = True
                self._reset_required = True

    def set_unreachable(self, unreachable: bool) -> None:
        """Simulate a cut cable or a dead controller."""
        with self._lock:
            self._unreachable = unreachable

    def manual_reset(self) -> bool:
        """The local, physical reset. Refuses while any demand is present --
        exactly as a real reset circuit does."""
        with self._lock:
            if self._estop_pressed or self._zone_violated or self._guard_open:
                return False
            self._latched = False
            self._reset_required = False
            return True

    # -- driver interface --------------------------------------------
    def read_status(self) -> SafetyStatus:
        with self._lock:
            if self._unreachable:
                return SafetyStatus.unreachable(self.device, "Simulated controller is unreachable.")
            return SafetyStatus(
                reachable=True,
                estop_clear=not self._estop_pressed and not self._latched,
                protective_stop_clear=not self._zone_violated and not self._latched,
                guards_closed=not self._guard_open,
                reset_required=self._reset_required,
                signals={
                    "estop_channel_a": not self._estop_pressed,
                    "estop_channel_b": not self._estop_pressed,
                    "zone_clear": not self._zone_violated,
                    "guard_closed": not self._guard_open,
                    "stop_latched": self._latched,
                },
                device=self.device,
                sampled_at=stamp(),
            )

    def request_stop(self, reason: str) -> bool:
        if self.stop_delay_s:
            time.sleep(self.stop_delay_s)
        with self._lock:
            self._stop_requests.append({"reason": reason[:200], "at": stamp()})
            self._latched = True
            self._reset_required = True
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "vendor": "fasp-harness",
            "model": "simulated-safety-controller",
            "real_hardware": self.IS_REAL_HARDWARE,
            "integrity_claim": "none -- this is a software model for testing, and carries no safety integrity whatsoever",
            "device": self.device,
            "stop_requests": len(self._stop_requests),
        }

    @property
    def stop_requests(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._stop_requests)


# A conventional, documented default map. Real integrations override it
# from the machine's own I/O schedule -- but shipping a plausible one makes
# the shape of the configuration obvious, and every entry is active-low
# because that is how a safety circuit is wired: a cut wire reads unsafe.
DEFAULT_SAFETY_SIGNALS = (
    SignalMapping("estop_channel_a", "discrete_input", 0, active_low=True, description="E-stop channel A, normally closed."),
    SignalMapping("estop_channel_b", "discrete_input", 1, active_low=True, description="E-stop channel B, normally closed."),
    SignalMapping("zone_violated", "discrete_input", 2, active_low=False, description="Safety-rated protective field violated."),
    SignalMapping("guard_open", "discrete_input", 3, active_low=False, description="Movable guard interlock open."),
    SignalMapping("reset_required", "discrete_input", 4, active_low=False, description="Controller is latched and awaits a local manual reset."),
)


class ModbusSafetyController:
    """Observe a safety PLC over Modbus/TCP, and request a stop over it.

    Two-channel E-stop inputs are read and compared: a persistent mismatch
    between channel A and channel B is a wiring or contact fault, and is
    reported as *not clear* rather than resolved by taking either channel's
    word for it.

    `stop_coil` is optional and, when present, is a *request* input on the
    controller -- a coil the safety program treats as one more demand
    source alongside the physical buttons. It is never a reset, and this
    class provides no way to write any other address.
    """

    IS_REAL_HARDWARE = True

    def __init__(
        self,
        host: str,
        port: int = 502,
        *,
        unit_id: int = 1,
        register_map: SafetyRegisterMap | None = None,
        stop_coil: int | None = None,
        timeout_s: float = 1.0,
        vendor: str = "unspecified",
        model: str = "unspecified",
        integrity_claim: str = "declared by the integrator; not verified by this software",
    ) -> None:
        self.client = ModbusTcpClient(host, port, unit_id=unit_id, timeout_s=timeout_s)
        self.register_map = register_map or SafetyRegisterMap(list(DEFAULT_SAFETY_SIGNALS))
        self.stop_coil = stop_coil
        self.device = f"modbus://{host}:{port}/{unit_id}"
        self.vendor = vendor
        self.model = model
        self.integrity_claim = integrity_claim

    def read_status(self) -> SafetyStatus:
        try:
            signals = self.register_map.read(self.client)
        except (ModbusError, FaspError) as error:
            return SafetyStatus.unreachable(self.device, error.detail)
        channel_a = signals.get("estop_channel_a", False)
        channel_b = signals.get("estop_channel_b", channel_a)
        channels_agree = channel_a == channel_b
        return SafetyStatus(
            reachable=True,
            estop_clear=channel_a and channel_b and channels_agree,
            protective_stop_clear=not signals.get("zone_violated", True),
            guards_closed=not signals.get("guard_open", True),
            reset_required=signals.get("reset_required", False),
            signals=signals,
            device=self.device,
            sampled_at=stamp(),
            detail="" if channels_agree else "E-stop channel discrepancy: treat as not clear and inspect the circuit.",
        )

    def request_stop(self, reason: str) -> bool:
        del reason
        if self.stop_coil is None:
            return False
        try:
            self.client.write_coil(self.stop_coil, True)
        except (ModbusError, FaspError):
            return False
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "model": self.model,
            "real_hardware": self.IS_REAL_HARDWARE,
            "integrity_claim": self.integrity_claim,
            "device": self.device,
            "stop_request_coil": self.stop_coil,
            "signals": self.register_map.describe(),
        }

    def close(self) -> None:
        self.client.close()
