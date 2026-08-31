"""Core primitives for the Federated Autonomous Systems Protocol harness.

The harness deliberately provides coordination, not remote code execution.
Model-specific behaviour is supplied by an Adapter and remains subject to the
local capability and risk policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from .crypto.envelope import FaspError, b64, sign, unb64, unsigned, verify
from .crypto.identity import Identity
from .platforms import runtime_profile

__all__ = [
    "FaspError",
    "Identity",
    "JsonState",
    "DefaultSafeAdapter",
    "FaspHarness",
    "SafeAdapter",
    "b64",
    "unb64",
    "sign",
    "verify",
    "unsigned",
    "now",
    "stamp",
    "parse_stamp",
    "PROTOCOL",
    "MAX_INLINE_BYTES",
    "MAX_CLOCK_SKEW_SECONDS",
]

PROTOCOL = "fasp/1.0"
MAX_INLINE_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 60


def now() -> datetime:
    return datetime.now(UTC)


def stamp(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _plain_json(value: Any) -> bytes:
    """Deterministic-enough local bookkeeping serialization.

    Deliberately NOT the RFC 8785 canonicalizer in `.crypto.canonical`: that
    canonicalizer enforces the IEEE 754 safe-integer domain (+-2**53-1),
    which is correct for anything that gets signed but wrong for purely
    local state such as `time.monotonic_ns()` bookkeeping fields, which
    routinely exceed it. Nothing written through `JsonState` is signed --
    signed records are canonicalized once, explicitly, by `sign()`/`verify()`
    before they ever reach here.
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_plain_json(value) + b"\n")
    os.replace(temporary, path)
    os.chmod(path, 0o600)


class JsonState:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def get(self, name: str, default: Any) -> Any:
        path = self.directory / name
        with self.lock:
            if not path.exists():
                return default
            return json.loads(path.read_text(encoding="utf-8"))

    def put(self, name: str, value: Any) -> None:
        with self.lock:
            atomic_json(self.directory / name, value)

    def append_jsonl(self, name: str, value: dict[str, Any]) -> None:
        path = self.directory / name
        with self.lock, path.open("a", encoding="utf-8") as output:
            output.write(_plain_json(value).decode() + "\n")
        os.chmod(path, 0o600)

    def read_jsonl(self, name: str) -> list[dict[str, Any]]:
        path = self.directory / name
        with self.lock:
            if not path.exists():
                return []
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class SafeAdapter(Protocol):
    """Model integration boundary. It never receives raw peer authority."""

    def capabilities(self) -> list[dict[str, Any]]: ...

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]: ...


class DefaultSafeAdapter:
    """Safe example adapter suitable for tests and initial deployments."""

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 5, "network": "none"},
            {"id": "coordinate.chat.v1", "risk": "observe", "max_runtime_s": 5, "network": "none"},
        ]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        capability = intent.get("capability")
        if capability == "observe.system.status.v1":
            return {"status": "ok", "summary": "Endpoint is online; no private host data exposed."}
        if capability == "coordinate.chat.v1":
            return {"status": "ok", "summary": str(intent.get("objective", ""))[:500]}
        raise FaspError("capability.unavailable", "Capability is not enabled by this adapter.")


class FaspHarness:
    """Durable FASP state machine behind the HTTP server."""

    def __init__(self, state_dir: Path, display_name: str, base_url: str, adapter: SafeAdapter | None = None) -> None:
        self.state = JsonState(state_dir)
        self.identity = Identity.load_or_create(state_dir / "identity.json")
        self.display_name = display_name
        self.base_url = base_url.rstrip("/")
        self.adapter = adapter or DefaultSafeAdapter()
        # Local import avoids a circular dependency: stream frames use FASP
        # encoding helpers, while the harness owns stream authorization.
        from .streaming import StreamRegistry
        from .robotics import ReservationBook
        self.streams = StreamRegistry(self.state)
        self.reservations = ReservationBook(self.state)
        if not (state_dir / "admin_token").exists():
            token = secrets.token_urlsafe(32)
            (state_dir / "admin_token").write_text(token + "\n", encoding="utf-8")
            os.chmod(state_dir / "admin_token", 0o600)

    @property
    def admin_token(self) -> str:
        return (self.state.directory / "admin_token").read_text(encoding="utf-8").strip()

    def id_card(self) -> dict[str, Any]:
        card = {
            "fasp": PROTOCOL,
            "type": "id_card",
            "system_id": self.identity.system_id,
            "display_name": self.display_name,
            "runtime": runtime_profile(),
            "public_key": self.identity.public_b64,
            "endpoints": {
                "hello": self.base_url + "/hello",
                "send": self.base_url + "/send",
                "task": self.base_url + "/task",
                "inbox": self.base_url + "/inbox",
                "receipt": self.base_url + "/receipt",
                "capabilities": self.base_url + "/capabilities",
                "id_card": self.base_url + "/id_card",
            },
            "capabilities": self.adapter.capabilities(),
            "issued_at": stamp(),
            "expires_at": stamp(now() + timedelta(days=30)),
        }
        return sign(card, self.identity.private, self.identity.kid)

    @staticmethod
    def verify_id_card(card: dict[str, Any]) -> None:
        required = {"fasp", "type", "system_id", "public_key", "endpoints", "expires_at", "signature"}
        if not required.issubset(card) or card.get("fasp") != PROTOCOL or card.get("type") != "id_card":
            raise FaspError("schema.invalid", "Invalid FASP ID card.")
        if parse_stamp(card["expires_at"]) <= now():
            raise FaspError("auth.card_expired", "ID card has expired.")
        verify(card, card["public_key"])
        raw = unb64(card["public_key"])
        expected = "fasp:system:" + b64(hashlib.sha256(raw).digest())
        if card["system_id"] != expected:
            raise FaspError("auth.identity_mismatch", "ID card identity does not match its public key.")

    def hello(self, card: dict[str, Any]) -> dict[str, Any]:
        self.verify_id_card(card)
        if card["system_id"] == self.identity.system_id:
            raise FaspError("auth.self_pairing", "A system cannot pair with itself.")
        peers = self.state.get("peers.json", {})
        fingerprint = b64(hashlib.sha256("|".join(sorted([self.identity.system_id, card["system_id"]])).encode()).digest())[:12]
        peers[card["system_id"]] = {
            "card": card,
            "state": peers.get(card["system_id"], {}).get("state", "pending"),
            "pair_code": fingerprint,
            "seen_at": stamp(),
            "allowed_capability_prefixes": peers.get(card["system_id"], {}).get("allowed_capability_prefixes", ["observe.", "coordinate."]),
        }
        self.state.put("peers.json", peers)
        return sign({"fasp": PROTOCOL, "type": "hello.ready", "system_id": self.identity.system_id, "id_card": self.id_card(), "pair_code": fingerprint, "pairing_required": peers[card["system_id"]]["state"] != "paired", "issued_at": stamp()}, self.identity.private, self.identity.kid)

    def confirm_peer(self, peer_id: str, pair_code: str, prefixes: list[str] | None = None) -> dict[str, Any]:
        peers = self.state.get("peers.json", {})
        peer = peers.get(peer_id)
        if not peer or not secrets.compare_digest(peer.get("pair_code", ""), pair_code):
            raise FaspError("auth.pairing_not_found", "Peer or pair code is invalid.")
        peer["state"] = "paired"
        peer["paired_at"] = stamp()
        if prefixes is not None:
            peer["allowed_capability_prefixes"] = prefixes
        peers[peer_id] = peer
        self.state.put("peers.json", peers)
        return {"ok": True, "peer_id": peer_id, "state": "paired", "allowed_capability_prefixes": peer["allowed_capability_prefixes"]}

    def _peer(self, peer_id: str) -> dict[str, Any]:
        peer = self.state.get("peers.json", {}).get(peer_id)
        if not peer or peer.get("state") != "paired":
            raise FaspError("auth.not_paired", "Peer is not paired and authorized.")
        return peer

    def make_envelope(self, kind: str, to: str, payload: dict[str, Any], conversation_id: str | None = None, causation_id: str | None = None) -> dict[str, Any]:
        issued = now()
        envelope = {
            "fasp": PROTOCOL,
            "kind": kind,
            "message_id": str(uuid.uuid4()),
            "conversation_id": conversation_id or str(uuid.uuid4()),
            "causation_id": causation_id,
            "from": self.identity.system_id,
            "to": to,
            "issued_at": stamp(issued),
            "expires_at": stamp(issued + timedelta(minutes=2)),
            "nonce": b64(secrets.token_bytes(12)),
            "payload": payload,
        }
        return sign(envelope, self.identity.private, self.identity.kid)

    def _verify_envelope(self, envelope: dict[str, Any], expected_kind: str | None = None) -> dict[str, Any]:
        required = {"fasp", "kind", "message_id", "from", "to", "issued_at", "expires_at", "nonce", "payload", "signature"}
        if not required.issubset(envelope) or envelope.get("fasp") != PROTOCOL:
            raise FaspError("schema.invalid", "Envelope misses required FASP fields.")
        if expected_kind and envelope["kind"] != expected_kind:
            raise FaspError("protocol.unsupported_kind", f"Endpoint requires {expected_kind}.")
        if envelope["to"] != self.identity.system_id:
            raise FaspError("auth.wrong_audience", "Envelope is addressed to another system.")
        try:
            issued, expires = parse_stamp(envelope["issued_at"]), parse_stamp(envelope["expires_at"])
        except (TypeError, ValueError) as exc:
            raise FaspError("schema.invalid", "Envelope timestamps are invalid.") from exc
        if expires <= now() or issued > now() + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            raise FaspError("auth.envelope_expired", "Envelope is expired or issued too far in the future.")
        if len(_plain_json(envelope)) > MAX_INLINE_BYTES:
            raise FaspError("resource.too_large", "Inline envelope exceeds 64 KiB.")
        peer = self._peer(envelope["from"])
        verify(envelope, peer["card"]["public_key"])
        return peer

    def accept(self, envelope: dict[str, Any], expected_kind: str | None = None) -> tuple[bool, dict[str, Any] | None]:
        peer = self._verify_envelope(envelope, expected_kind)
        seen = self.state.get("seen.json", {})
        if envelope["message_id"] in seen:
            return True, seen[envelope["message_id"]].get("response")
        self.state.append_jsonl("inbox.jsonl", envelope)
        response: dict[str, Any] | None = None
        if envelope["kind"] == "intent.propose":
            response = self._handle_intent(envelope, peer)
        seen[envelope["message_id"]] = {"processed_at": stamp(), "response": response}
        self.state.put("seen.json", dict(list(seen.items())[-5000:]))
        return False, response

    def _handle_intent(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        intent = envelope["payload"]
        key = intent.get("idempotency_key")
        capability = intent.get("capability", "")
        if not isinstance(key, str) or not key or not isinstance(capability, str):
            raise FaspError("schema.invalid", "Intent requires idempotency_key and capability.")
        if not any(capability.startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Paired peer is not granted this capability prefix.")
        capabilities = {item["id"]: item for item in self.adapter.capabilities()}
        if capability not in capabilities:
            raise FaspError("capability.unavailable", "Capability is unavailable at this runtime.")
        if intent.get("risk", capabilities[capability]["risk"]) not in {"observe", "reversible"}:
            raise FaspError("policy.requires_confirmation", "This harness requires explicit local approval for this risk class.")
        journal = self.state.get("tasks.json", {})
        if key in journal:
            return journal[key]["result"]
        try:
            output = self.adapter.handle(intent)
            result = {"type": "task.result", "intent_id": intent.get("intent_id"), "idempotency_key": key, "status": "completed", "output": output, "completed_at": stamp()}
        except FaspError as error:
            result = {"type": "task.fail", "intent_id": intent.get("intent_id"), "idempotency_key": key, "status": "failed", "error": {"code": error.code, "detail": error.detail}, "completed_at": stamp()}
        journal[key] = {"result": result, "from": envelope["from"]}
        self.state.put("tasks.json", journal)
        return result

    def pull_inbox(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._verify_envelope(envelope, "inbox.pull")
        cursor = float(envelope["payload"].get("cursor", 0))
        messages = [item for item in self.state.read_jsonl("inbox.jsonl") if parse_stamp(item["issued_at"]).timestamp() > cursor]
        return {"messages": messages, "cursor": now().timestamp()}

    def receipt(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._verify_envelope(envelope, "receipt.processed")
        payload = envelope["payload"]
        if not isinstance(payload.get("message_id"), str):
            raise FaspError("schema.invalid", "Receipt requires message_id.")
        receipts = self.state.get("receipts.json", {})
        receipts[payload["message_id"]] = {"from": envelope["from"], "processed_at": stamp()}
        self.state.put("receipts.json", receipts)
        return {"ok": True}

    def _stream_authorize(self, envelope: dict[str, Any], kind: str) -> dict[str, Any]:
        peer = self._verify_envelope(envelope, kind)
        capability = envelope["payload"].get("capability", "observe.stream.v1")
        if not isinstance(capability, str) or not any(capability.startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Paired peer is not authorized for this stream capability.")
        return peer

    def stream_open(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._stream_authorize(envelope, "stream.open")
        return self.streams.open(envelope["from"], envelope["payload"])

    def stream_packet(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._stream_authorize(envelope, "stream.packet")
        return self.streams.packet(envelope["from"], envelope["payload"])

    def stream_pull(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._stream_authorize(envelope, "stream.pull")
        payload = envelope["payload"]
        if not isinstance(payload.get("stream_id"), str):
            raise FaspError("schema.invalid", "stream.pull requires stream_id.")
        return self.streams.pull(envelope["from"], payload["stream_id"], int(payload.get("after_sequence", -1)))

    def stream_close(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._stream_authorize(envelope, "stream.close")
        payload = envelope["payload"]
        if not isinstance(payload.get("stream_id"), str):
            raise FaspError("schema.invalid", "stream.close requires stream_id.")
        return self.streams.close(envelope["from"], payload["stream_id"], str(payload.get("reason", "closed")))

    def reservation_request(self, envelope: dict[str, Any]) -> dict[str, Any]:
        peer = self._verify_envelope(envelope, "reservation.request")
        if not any("fleet.reserve.v1".startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Peer is not authorized for fleet reservations.")
        return self.reservations.request(envelope["from"], envelope["payload"])

    def reservation_release(self, envelope: dict[str, Any]) -> dict[str, Any]:
        peer = self._verify_envelope(envelope, "reservation.release")
        if not any("fleet.reserve.v1".startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Peer is not authorized for fleet reservations.")
        reservation_id = envelope["payload"].get("reservation_id")
        if not isinstance(reservation_id, str):
            raise FaspError("schema.invalid", "reservation.release requires reservation_id.")
        return self.reservations.release(envelope["from"], reservation_id)
