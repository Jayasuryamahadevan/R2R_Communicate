"""Outbound-only relay transport for paired FASP nodes behind NAT."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..crypto.identity import atomic_json
from ..protocol.errors import FaspError
from ..timestamps import now, stamp
from .relay_wire import check_relay_url, relay_http

if TYPE_CHECKING:
    from ..core import FaspHarness


class RelayClient:
    def __init__(self, harness: FaspHarness, *, ca_cert: str | None = None, timeout: float = 5.0) -> None:
        self.harness = harness
        self.ca_cert = ca_cert
        self.timeout = timeout
        path = harness.state.directory / "relay-client.json"
        if not path.exists():
            raise FaspError("config.relay_missing", "Configure a relay with 'fasp relay-config'.")
        config = json.loads(path.read_text(encoding="utf-8"))
        self.url = check_relay_url(config["url"])
        self.token = config["token"]
        self.account = harness.identity.system_id

    @staticmethod
    def configure(state_dir: Path, url: str, token_file: Path) -> dict[str, Any]:
        url = check_relay_url(url)
        token = token_file.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise FaspError("config.invalid", "Relay token is too short.")
        atomic_json(state_dir / "relay-client.json", {"url": url, "token": token})
        return {"ok": True, "url": url, "state_dir": str(state_dir)}

    def _call(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return relay_http(self.url, self.account, self.token, method, path, payload, ca_cert=self.ca_cert, timeout=self.timeout)

    def _peer_card(self, peer_id: str) -> dict[str, Any]:
        self.harness._peer(peer_id)
        peer = self.harness.peers.get(peer_id)
        card = peer["card"]
        if not isinstance(card.get("relay_public_key"), str):
            raise FaspError("auth.invalid_relay_key", "Peer's pinned card has no relay key; reconnect and verify its new signed card.")
        return card

    def poll(self) -> list[dict[str, Any]]:
        result = self._call("GET", "/relay/v1/messages?limit=16")
        frames = result.get("frames")
        if not isinstance(frames, list) or len(frames) > 16:
            raise FaspError("transport.unreachable", "Relay returned an invalid mailbox batch.")
        return frames

    def ack(self, frame_id: int) -> None:
        self._call("POST", "/relay/v1/ack", {"id": frame_id})

    def send_request(self, peer_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
        card = self._peer_card(peer_id)
        frame = self.harness.relay_key.seal(self.harness.identity, peer_id, card["relay_public_key"], envelope["message_id"], "request", {"envelope": envelope}, envelope["expires_at"])
        self._call("POST", "/relay/v1/messages", {"frame": frame, "path": []})
        deadline = time.monotonic() + self.timeout
        while True:
            for entry in self.poll():
                reply = entry.get("frame")
                if not isinstance(reply, dict) or reply.get("kind") != "response" or reply.get("from") != peer_id or reply.get("message_id") != envelope["message_id"]:
                    continue
                body = self.harness.relay_key.open(reply, card, self.account)
                response = body.get("receipt")
                if not isinstance(response, dict) or response.get("type") != "receipt.delivered" or response.get("message_id") != envelope["message_id"]:
                    raise FaspError("auth.invalid_relay_frame", "Relay receipt does not match the request.")
                self.ack(entry["id"])
                return response if envelope.get("kind") in {"intent.propose", "task.cancel", "artifact.fetch"} else response.get("response", response)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FaspError("transport.response_unavailable", "Relay accepted the request; destination has not replied yet.")
            time.sleep(min(0.25, remaining))

    def process_once(self) -> dict[str, int]:
        report = {"received": 0, "replied": 0, "rejected": 0}
        for entry in self.poll():
            frame = entry.get("frame")
            if not isinstance(frame, dict) or frame.get("kind") != "request":
                continue
            report["received"] += 1
            sender = frame.get("from")
            peer = self.harness.peers.get(sender) if isinstance(sender, str) else None
            if peer is None or not isinstance(peer.get("card", {}).get("relay_public_key"), str):
                self.ack(entry["id"])
                report["rejected"] += 1
                continue
            try:
                body = self.harness.relay_key.open(frame, peer["card"], self.account)
                envelope = body.get("envelope")
                if not isinstance(envelope, dict) or envelope.get("message_id") != frame.get("message_id") or envelope.get("from") != sender or envelope.get("to") != self.account:
                    raise FaspError("auth.invalid_relay_frame", "Inner envelope does not match encrypted route.")
            except FaspError as exc:
                if exc.code.startswith(("auth.", "schema.")):
                    self.ack(entry["id"])
                    report["rejected"] += 1
                else:
                    raise
                continue
            try:
                _, outcome = self.harness.accept(envelope)
            except FaspError as exc:
                outcome = {"type": "protocol.error", "error": {"code": exc.code, "detail": exc.detail}}
            receipt = {"type": "receipt.delivered", "message_id": frame["message_id"], "response": outcome}
            response = self.harness.relay_key.seal(self.harness.identity, sender, peer["card"]["relay_public_key"], frame["message_id"], "response", {"receipt": receipt}, stamp(now() + timedelta(seconds=90)))
            self._call("POST", "/relay/v1/messages", {"frame": response, "path": []})
            self.ack(entry["id"])
            report["replied"] += 1
        return report
