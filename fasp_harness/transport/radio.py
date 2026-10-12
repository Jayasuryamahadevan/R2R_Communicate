"""Linux Bluetooth Classic RFCOMM and BLE L2CAP bearers for FASP.

Both bearers carry the same bounded JSON requests. The only executable
request is a signed envelope, dispatched by FaspHarness.accept(). Bluetooth
link pairing is an additional confidentiality and authentication layer, not
the FASP authorization decision.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from ..core import PROTOCOL, FaspHarness
from ..protocol.errors import FaspError
from .canonical import MAX_ENVELOPE_BYTES, accept_envelope, decode_object

logger = logging.getLogger(__name__)

MAX_REQUEST = MAX_ENVELOPE_BYTES + 256  # Envelope plus this bearer's JSON wrapper.
MAX_RESPONSE = 2 * 1024 * 1024
CHUNK_SIZE = 128  # Below the minimum practical LE CoC MTU.
DEFAULT_RFCOMM_CHANNEL = 8
DEFAULT_BLE_PSM = 0x0080
SOL_BLUETOOTH = getattr(socket, "SOL_BLUETOOTH", 274)
BT_SECURITY = getattr(socket, "BT_SECURITY", 4)
BT_SECURITY_HIGH = getattr(socket, "BT_SECURITY_HIGH", 3)


@dataclass(frozen=True)
class RadioEndpoint:
    mode: str
    address: str
    channel: int = DEFAULT_RFCOMM_CHANNEL
    psm: int = DEFAULT_BLE_PSM
    address_type: str = "public"

    def validate(self, *, listener: bool = False) -> None:
        if not isinstance(self.mode, str) or not isinstance(self.address_type, str):
            raise FaspError("schema.invalid", "Bluetooth mode and address type must be strings.")
        if type(self.channel) is not int or type(self.psm) is not int:
            raise FaspError("schema.invalid", "Bluetooth channel and PSM must be integers.")
        if self.mode not in {"classic", "ble"}:
            raise FaspError("schema.invalid", "Radio mode must be 'classic' or 'ble'.")
        if self.mode == "classic" and not 1 <= self.channel <= 30:
            raise FaspError("schema.invalid", "RFCOMM channel must be 1..30.")
        if self.mode == "ble" and not 0x0080 <= self.psm <= 0x00FF:
            raise FaspError("schema.invalid", "BLE LE_PSM must be 0x0080..0x00ff.")
        if self.address_type not in {"public", "random"}:
            raise FaspError("schema.invalid", "BLE address type must be public or random.")
        if not isinstance(self.address, str) or len(self.address.split(":")) != 6 or any(
            len(part) != 2 or any(char not in "0123456789abcdefABCDEF" for char in part) for part in self.address.split(":")
        ):
            raise FaspError("schema.invalid", "Expected a six-byte Bluetooth address.")
        if not listener and self.address == "00:00:00:00:00:00":
            raise FaspError("schema.invalid", "A remote Bluetooth address is required.")

    def socket_address(self) -> tuple[Any, ...]:
        self.validate(listener=self.address == "00:00:00:00:00:00")
        if self.mode == "classic":
            return (self.address, self.channel)
        # Python 3.14 added the LE address type to sockaddr_l2. Earlier
        # versions silently use BR/EDR and cannot establish this BLE bearer.
        if not hasattr(socket, "BDADDR_LE_PUBLIC"):
            raise FaspError("transport.unsupported", "BLE L2CAP requires Python 3.14+ on Linux.")
        kind = socket.BDADDR_LE_PUBLIC if self.address_type == "public" else socket.BDADDR_LE_RANDOM
        return (self.address, self.psm, 0, kind)

    def as_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "address": self.address, "channel": self.channel, "psm": self.psm, "address_type": self.address_type}

    @classmethod
    def from_dict(cls, value: Any) -> RadioEndpoint:
        if not isinstance(value, dict):
            raise FaspError("schema.invalid", "Radio endpoint must be an object.")
        try:
            endpoint = cls(**value)
        except TypeError as exc:
            raise FaspError("schema.invalid", "Radio endpoint has invalid fields.") from exc
        endpoint.validate()
        return endpoint


def _new_socket(mode: str) -> socket.socket:
    if sys.platform != "linux" or not hasattr(socket, "AF_BLUETOOTH"):
        raise FaspError("transport.unsupported", "Linux Bluetooth sockets with BT_SECURITY are required.")
    if mode == "classic":
        connection = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    else:
        connection = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    try:
        # struct bt_security { uint8_t level, key_size }. A failed set is
        # fatal: accepting an unauthenticated link would expose payloads.
        connection.setsockopt(SOL_BLUETOOTH, BT_SECURITY, bytes((BT_SECURITY_HIGH, 0)))
        connection.settimeout(10)
    except BaseException:
        connection.close()
        raise
    return connection


def _require_link_security(connection: socket.socket) -> None:
    level = connection.getsockopt(SOL_BLUETOOTH, BT_SECURITY, 2)[0]
    if level < BT_SECURITY_HIGH:
        raise FaspError("auth.bluetooth_security", "Bluetooth link is below authenticated encryption level.")


class FramedConnection:
    def __init__(self, connection: socket.socket, mode: str) -> None:
        self.connection = connection
        self.mode = mode
        self.buffer = bytearray()

    def _read(self, count: int) -> bytes:
        while len(self.buffer) < count:
            packet = self.connection.recv(4096 if self.mode == "classic" else CHUNK_SIZE)
            if not packet:
                raise ConnectionError("Bluetooth connection closed during a frame.")
            self.buffer.extend(packet)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def receive(self, limit: int) -> dict[str, Any]:
        size = struct.unpack(">I", self._read(4))[0]
        if not 0 < size <= limit:
            raise FaspError("resource.too_large", "Bluetooth frame exceeds the allowed size.")
        return decode_object(self._read(size), limit=limit)

    def send(self, value: dict[str, Any], limit: int) -> None:
        data = json.dumps(value, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(data) > limit:
            raise FaspError("resource.too_large", "Bluetooth response exceeds the allowed size.")
        frame = struct.pack(">I", len(data)) + data
        if self.mode == "ble":
            for offset in range(0, len(frame), CHUNK_SIZE):
                # One send per SEQPACKET preserves packet boundaries and
                # avoids truncation at the LE CoC MTU.
                packet = frame[offset : offset + CHUNK_SIZE]
                if self.connection.send(packet) != len(packet):
                    raise ConnectionError("Incomplete BLE packet write.")
        else:
            self.connection.sendall(frame)


def dispatch(harness: FaspHarness, request: dict[str, Any]) -> dict[str, Any]:
    kind = request.get("type")
    if kind == "profile":
        return harness.id_card()
    if kind == "pair.hello":
        card = request.get("id_card")
        if not isinstance(card, dict):
            raise FaspError("schema.invalid", "Pairing requires a signed ID card object.")
        return harness.hello(card)
    if kind == "envelope":
        envelope = request.get("envelope")
        if not isinstance(envelope, dict):
            raise FaspError("schema.invalid", "A signed envelope object is required.")
        return accept_envelope(harness, envelope)
    raise FaspError("protocol.unsupported_kind", "Unknown Bluetooth request type.")


def request_radio(endpoint: RadioEndpoint, payload: dict[str, Any], *, timeout: float = 10) -> dict[str, Any]:
    endpoint.validate()
    if not 0 < timeout <= 120:
        raise FaspError("schema.invalid", "Bluetooth timeout must be 0..120 seconds.")
    address = endpoint.socket_address()
    with _new_socket(endpoint.mode) as connection:
        connection.settimeout(timeout)
        connection.connect(address)
        _require_link_security(connection)
        wire = FramedConnection(connection, endpoint.mode)
        wire.send(payload, MAX_REQUEST)
        response = wire.receive(MAX_RESPONSE)
    if response.get("type") == "protocol.error":
        error = response.get("error", {})
        if not isinstance(error, dict):
            raise FaspError("schema.invalid", "Bluetooth peer returned an invalid protocol error.")
        raise FaspError(str(error.get("code", "protocol.error")), str(error.get("detail", "Remote request rejected.")))
    return response


class RadioListener:
    def __init__(self, harness: FaspHarness, endpoint: RadioEndpoint) -> None:
        endpoint.validate(listener=True)
        self.harness = harness
        self.endpoint = endpoint
        self.listener: socket.socket | None = None
        self.stopping = threading.Event()
        self.thread: threading.Thread | None = None
        self.capacity = threading.BoundedSemaphore(8)
        self.workers = ThreadPoolExecutor(max_workers=8, thread_name_prefix=f"fasp-{endpoint.mode}")

    def start(self) -> None:
        address = self.endpoint.socket_address()
        listener = _new_socket(self.endpoint.mode)
        try:
            listener.bind(address)
            listener.listen(8)
            listener.settimeout(0.5)
        except BaseException:
            listener.close()
            raise
        self.listener = listener
        self.thread = threading.Thread(target=self._run, name=f"fasp-{self.endpoint.mode}-listener", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        assert self.listener is not None
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.stopping.is_set():
                    logger.exception("Bluetooth listener stopped unexpectedly")
                break
            if self.stopping.is_set():
                connection.close()
                break
            if not self.capacity.acquire(blocking=False):
                connection.close()
                continue
            try:
                self.workers.submit(self._handle, connection)
            except RuntimeError:
                self.capacity.release()
                connection.close()
                break

    def _handle(self, connection: socket.socket) -> None:
        try:
            with connection:
                connection.settimeout(10)
                _require_link_security(connection)
                wire = FramedConnection(connection, self.endpoint.mode)
                try:
                    response = dispatch(self.harness, wire.receive(MAX_REQUEST))
                except FaspError as error:
                    self.harness.metrics.increment("fasp_auth_failures_total", code=error.code)
                    response = {"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}}
                try:
                    wire.send(response, MAX_RESPONSE)
                except FaspError as error:
                    wire.send({"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}}, MAX_RESPONSE)
        except (OSError, ConnectionError, FaspError):
            logger.debug("Bluetooth request disconnected or failed", exc_info=True)
        except Exception:
            logger.exception("Unexpected Bluetooth request failure")
        finally:
            self.capacity.release()

    def close(self) -> None:
        self.stopping.set()
        if self.listener is not None:
            self.listener.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        self.workers.shutdown(wait=True)
