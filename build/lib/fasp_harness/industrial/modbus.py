"""Modbus/TCP: codec, client, and an in-process server for tests and HIL.

Modbus is how a Layer 3 coordinator usually gets to *see* Layer 1. A safety
PLC or safety relay exposes its state -- E-stop channel A/B, muting status,
zone violated, guard closed, reset required -- as discrete inputs; the
coordinator reads them and forms an opinion. That direction, read-only, is
the whole point: `fasp_harness.layers` permits OBSERVE toward Layer 1 and
nothing else, and `SafetyRegisterMap` below makes that structural by
refusing to build a write for an address marked safety-relevant.

Implemented here rather than pulled in as a dependency because the subset
is genuinely small (one framing header and seven function codes), because
a safety-adjacent read path is exactly where an unaudited transitive
dependency tree is least welcome, and because the simulator has to speak
the same bytes as the client for the tests to prove anything.

Reference: MODBUS Application Protocol Specification V1.1b3 and MODBUS
Messaging on TCP/IP Implementation Guide V1.0b.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
from dataclasses import dataclass, field
from typing import Any

from ..protocol.errors import FaspError

MBAP_HEADER = struct.Struct(">HHHB")
MBAP_SIZE = 7
MAX_PDU_BYTES = 253
DEFAULT_PORT = 502

# Function codes (MODBUS V1.1b3 section 6).
READ_COILS = 0x01
READ_DISCRETE_INPUTS = 0x02
READ_HOLDING_REGISTERS = 0x03
READ_INPUT_REGISTERS = 0x04
WRITE_SINGLE_COIL = 0x05
WRITE_SINGLE_REGISTER = 0x06
WRITE_MULTIPLE_REGISTERS = 0x10

EXCEPTION_MESSAGES = {
    0x01: "Illegal function",
    0x02: "Illegal data address",
    0x03: "Illegal data value",
    0x04: "Server device failure",
    0x05: "Acknowledge",
    0x06: "Server device busy",
    0x08: "Memory parity error",
    0x0A: "Gateway path unavailable",
    0x0B: "Gateway target device failed to respond",
}


class ModbusError(FaspError):
    """A Modbus-level failure, safe to report to a peer (no host detail)."""

    def __init__(self, detail: str, *, code: str = "transport.unreachable") -> None:
        super().__init__(code, detail)


class ModbusExceptionResponse(ModbusError):
    def __init__(self, function: int, exception_code: int) -> None:
        text = EXCEPTION_MESSAGES.get(exception_code, "Unknown exception")
        super().__init__(f"Modbus function 0x{function:02X} returned exception 0x{exception_code:02X} ({text}).", code="capability.unavailable")
        self.function = function
        self.exception_code = exception_code


def _check_quantity(quantity: int, maximum: int) -> None:
    if not 1 <= quantity <= maximum:
        raise ModbusError(f"Quantity must be between 1 and {maximum}.", code="schema.invalid")


def _check_address(address: int) -> None:
    if not 0 <= address <= 0xFFFF:
        raise ModbusError("Address must fit in 16 bits.", code="schema.invalid")


def unpack_bits(payload: bytes, quantity: int) -> list[bool]:
    """Modbus packs coil/input status LSB-first within each byte."""
    return [bool(payload[index // 8] >> (index % 8) & 1) for index in range(quantity)]


def pack_bits(values: list[bool]) -> bytes:
    packed = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            packed[index // 8] |= 1 << (index % 8)
    return bytes(packed)


@dataclass
class ModbusDataStore:
    """The four Modbus address spaces, as a plain in-memory model.

    Used by the simulator, and by tests that need a deterministic Layer 1
    stand-in whose exact bit pattern they control.
    """

    coils: dict[int, bool] = field(default_factory=dict)
    discrete_inputs: dict[int, bool] = field(default_factory=dict)
    holding_registers: dict[int, int] = field(default_factory=dict)
    input_registers: dict[int, int] = field(default_factory=dict)
    read_only_coils: set[int] = field(default_factory=set)

    def read_bits(self, space: dict[int, bool], address: int, quantity: int) -> list[bool]:
        return [bool(space.get(address + offset, False)) for offset in range(quantity)]

    def read_registers(self, space: dict[int, int], address: int, quantity: int) -> list[int]:
        return [int(space.get(address + offset, 0)) & 0xFFFF for offset in range(quantity)]


class _ModbusRequestHandler(socketserver.BaseRequestHandler):
    """One connection. Reads MBAP-framed requests until the peer closes."""

    def handle(self) -> None:
        store: ModbusDataStore = self.server.store  # type: ignore[attr-defined]
        self.request.settimeout(5.0)
        while True:
            header = _recv_exactly(self.request, MBAP_SIZE)
            if header is None:
                return
            transaction, protocol, length, unit = MBAP_HEADER.unpack(header)
            if protocol != 0 or not 2 <= length <= MAX_PDU_BYTES + 1:
                return
            body = _recv_exactly(self.request, length - 1)
            if body is None:
                return
            self.server.request_count += 1  # type: ignore[attr-defined]
            response_pdu = _serve_pdu(store, body)
            self.request.sendall(MBAP_HEADER.pack(transaction, 0, len(response_pdu) + 1, unit) + response_pdu)


def _serve_pdu(store: ModbusDataStore, pdu: bytes) -> bytes:
    """Apply one request PDU to `store`, returning the response PDU."""
    if not pdu:
        return bytes([0x80, 0x03])
    function = pdu[0]
    try:
        if function in (READ_COILS, READ_DISCRETE_INPUTS):
            address, quantity = struct.unpack(">HH", pdu[1:5])
            if not 1 <= quantity <= 2000:
                return bytes([function | 0x80, 0x03])
            space = store.coils if function == READ_COILS else store.discrete_inputs
            payload = pack_bits(store.read_bits(space, address, quantity))
            return bytes([function, len(payload)]) + payload
        if function in (READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
            address, quantity = struct.unpack(">HH", pdu[1:5])
            if not 1 <= quantity <= 125:
                return bytes([function | 0x80, 0x03])
            space = store.holding_registers if function == READ_HOLDING_REGISTERS else store.input_registers
            values = store.read_registers(space, address, quantity)
            return bytes([function, quantity * 2]) + b"".join(struct.pack(">H", value) for value in values)
        if function == WRITE_SINGLE_COIL:
            address, value = struct.unpack(">HH", pdu[1:5])
            if value not in (0x0000, 0xFF00):
                return bytes([function | 0x80, 0x03])
            if address in store.read_only_coils:
                return bytes([function | 0x80, 0x02])
            store.coils[address] = value == 0xFF00
            return pdu[:5]
        if function == WRITE_SINGLE_REGISTER:
            address, value = struct.unpack(">HH", pdu[1:5])
            store.holding_registers[address] = value
            return pdu[:5]
        if function == WRITE_MULTIPLE_REGISTERS:
            address, quantity, byte_count = struct.unpack(">HHB", pdu[1:6])
            if byte_count != quantity * 2 or len(pdu) < 6 + byte_count:
                return bytes([function | 0x80, 0x03])
            for offset in range(quantity):
                (value,) = struct.unpack(">H", pdu[6 + offset * 2 : 8 + offset * 2])
                store.holding_registers[address + offset] = value
            return struct.pack(">BHH", function, address, quantity)
    except struct.error:
        return bytes([function | 0x80, 0x03])
    return bytes([function | 0x80, 0x01])


def _recv_exactly(sock: socket.socket, count: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < count:
        try:
            chunk = sock.recv(count - len(chunks))
        except (TimeoutError, OSError):
            return None
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


class ModbusTcpServer(socketserver.ThreadingTCPServer):
    """A real Modbus/TCP listener over a real socket.

    Deliberately a genuine server rather than a mocked client: the tests
    that matter here are about bytes on a wire, and a simulator that shares
    the client's own encoder proves nothing about either.
    """

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, store: ModbusDataStore, host: str = "127.0.0.1", port: int = 0) -> None:
        super().__init__((host, port), _ModbusRequestHandler)
        self.store = store
        self.request_count = 0

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def start(self) -> ModbusTcpServer:
        threading.Thread(target=self.serve_forever, name="fasp-modbus-sim", daemon=True).start()
        return self

    def __enter__(self) -> ModbusTcpServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.shutdown()
        self.server_close()


class ModbusTcpClient:
    """A minimal, synchronous, reconnecting Modbus/TCP client."""

    def __init__(self, host: str, port: int = DEFAULT_PORT, *, unit_id: int = 1, timeout_s: float = 2.0) -> None:
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout_s = timeout_s
        self._socket: socket.socket | None = None
        self._transaction = 0
        self._lock = threading.Lock()

    # -- connection --------------------------------------------------
    def connect(self) -> None:
        with self._lock:
            self._connect_locked()

    def _connect_locked(self) -> None:
        if self._socket is not None:
            return
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
        except OSError as exc:
            raise ModbusError(f"Cannot reach the Modbus device at port {self.port}: {exc.__class__.__name__}.") from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._socket = sock

    def close(self) -> None:
        with self._lock:
            sock, self._socket = self._socket, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def __enter__(self) -> ModbusTcpClient:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transaction -------------------------------------------------
    def _transact(self, pdu: bytes) -> bytes:
        with self._lock:
            self._connect_locked()
            assert self._socket is not None
            self._transaction = expected = (self._transaction + 1) & 0xFFFF
            frame = MBAP_HEADER.pack(expected, 0, len(pdu) + 1, self.unit_id) + pdu
            try:
                self._socket.sendall(frame)
                header = _recv_exactly(self._socket, MBAP_SIZE)
                if header is None:
                    raise ModbusError("Modbus device closed the connection before replying.")
                transaction, protocol, length, _unit = MBAP_HEADER.unpack(header)
                if protocol != 0 or not 2 <= length <= MAX_PDU_BYTES + 1:
                    raise ModbusError("Modbus reply has an invalid MBAP header.", code="schema.invalid")
                body = _recv_exactly(self._socket, length - 1)
                if body is None:
                    raise ModbusError("Modbus reply was truncated.")
            except ModbusError:
                self._drop_locked()
                raise
            except OSError as exc:
                self._drop_locked()
                raise ModbusError(f"Modbus I/O failed: {exc.__class__.__name__}.") from exc
        if transaction != expected:
            raise ModbusError("Modbus reply transaction identifier does not match the request.", code="schema.invalid")
        if body[0] & 0x80:
            raise ModbusExceptionResponse(body[0] & 0x7F, body[1] if len(body) > 1 else 0)
        if body[0] != pdu[0]:
            raise ModbusError("Modbus reply function code does not match the request.", code="schema.invalid")
        return body

    def _drop_locked(self) -> None:
        sock, self._socket = self._socket, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # -- read ---------------------------------------------------------
    def read_coils(self, address: int, quantity: int = 1) -> list[bool]:
        _check_address(address)
        _check_quantity(quantity, 2000)
        return unpack_bits(self._transact(struct.pack(">BHH", READ_COILS, address, quantity))[2:], quantity)

    def read_discrete_inputs(self, address: int, quantity: int = 1) -> list[bool]:
        _check_address(address)
        _check_quantity(quantity, 2000)
        return unpack_bits(self._transact(struct.pack(">BHH", READ_DISCRETE_INPUTS, address, quantity))[2:], quantity)

    def read_holding_registers(self, address: int, quantity: int = 1) -> list[int]:
        _check_address(address)
        _check_quantity(quantity, 125)
        body = self._transact(struct.pack(">BHH", READ_HOLDING_REGISTERS, address, quantity))
        return [value for (value,) in struct.iter_unpack(">H", body[2 : 2 + quantity * 2])]

    def read_input_registers(self, address: int, quantity: int = 1) -> list[int]:
        _check_address(address)
        _check_quantity(quantity, 125)
        body = self._transact(struct.pack(">BHH", READ_INPUT_REGISTERS, address, quantity))
        return [value for (value,) in struct.iter_unpack(">H", body[2 : 2 + quantity * 2])]

    # -- write --------------------------------------------------------
    def write_coil(self, address: int, value: bool) -> None:
        _check_address(address)
        self._transact(struct.pack(">BHH", WRITE_SINGLE_COIL, address, 0xFF00 if value else 0x0000))

    def write_register(self, address: int, value: int) -> None:
        _check_address(address)
        if not 0 <= value <= 0xFFFF:
            raise ModbusError("Register values are 16-bit.", code="schema.invalid")
        self._transact(struct.pack(">BHH", WRITE_SINGLE_REGISTER, address, value))

    def write_registers(self, address: int, values: list[int]) -> None:
        _check_address(address)
        _check_quantity(len(values), 123)
        payload = b"".join(struct.pack(">H", value & 0xFFFF) for value in values)
        self._transact(struct.pack(">BHHB", WRITE_MULTIPLE_REGISTERS, address, len(values), len(payload)) + payload)


@dataclass(frozen=True)
class SignalMapping:
    """One named boolean signal at a Modbus address."""

    name: str
    space: str
    address: int
    active_low: bool = False
    safety_relevant: bool = True
    description: str = ""

    def evaluate(self, raw: bool) -> bool:
        return (not raw) if self.active_low else raw


class SafetyRegisterMap:
    """A named, read-only view of a safety controller's status bits.

    The class exists to make one mistake impossible to make quietly. Every
    signal defaults to `safety_relevant=True`, and `writable_signal()`
    refuses to produce a write path for any such signal -- so wiring
    "clear the E-stop" to a network handler is not an oversight away, it is
    an exception at configuration time.

    Signals are declared active-low where the field wiring is (a safety
    circuit is normally wired so that a broken wire reads as *unsafe*),
    which is a detail worth modelling explicitly rather than inverting by
    hand at every call site.
    """

    def __init__(self, signals: list[SignalMapping]) -> None:
        self.signals = {signal.name: signal for signal in signals}
        if len(self.signals) != len(signals):
            raise FaspError("schema.invalid", "Duplicate signal name in the safety register map.")

    def read(self, client: ModbusTcpClient) -> dict[str, bool]:
        """Read every declared signal. Grouped per address space and read as
        one contiguous block per space, so the sample is as close to
        simultaneous as Modbus allows -- signals read in separate
        transactions can disagree about the same instant."""
        result: dict[str, bool] = {}
        for space in {signal.space for signal in self.signals.values()}:
            in_space = [signal for signal in self.signals.values() if signal.space == space]
            low = min(signal.address for signal in in_space)
            high = max(signal.address for signal in in_space)
            reader = {"coil": client.read_coils, "discrete_input": client.read_discrete_inputs}.get(space)
            if reader is None:
                raise FaspError("schema.invalid", f"Unsupported Modbus bit space {space!r}.")
            block = reader(low, high - low + 1)
            for signal in in_space:
                result[signal.name] = signal.evaluate(block[signal.address - low])
        return result

    def writable_signal(self, name: str) -> SignalMapping:
        """Return `name` only if writing it is not a safety function."""
        signal = self.signals.get(name)
        if signal is None:
            raise FaspError("schema.invalid", f"Unknown signal {name!r}.")
        if signal.safety_relevant:
            raise FaspError(
                "policy.layer_violation",
                f"Signal {name!r} is safety-relevant; FASP observes Layer 1 and never writes to it.",
            )
        return signal

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": signal.name, "space": signal.space, "address": signal.address, "active_low": signal.active_low, "safety_relevant": signal.safety_relevant, "description": signal.description}
            for signal in sorted(self.signals.values(), key=lambda item: (item.space, item.address))
        ]
