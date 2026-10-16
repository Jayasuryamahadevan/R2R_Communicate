"""Bounded HTTPS mailbox for NATed FASP nodes and static relay chains.

The hub stores opaque, end-to-end encrypted frames. Every client reaches it
outbound. A route to another hub forwards the same ciphertext with a bounded
hop trace; the origin's outbox retries if a downstream hub is unavailable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..crypto.identity import atomic_json
from ..protocol.errors import FaspError
from .relay_wire import relay_http

MAX_FRAME_BYTES = 96 * 1024
MAX_HOPS = 4
MAX_MAILBOX = 128
MAX_TOTAL_FRAMES = 4096
MAX_TTL_SECONDS = 120


class RelayHub:
    def __init__(self, state_dir: Path) -> None:
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_dir = state_dir
        self._lock = threading.RLock()
        hub_file = state_dir / "hub.json"
        if hub_file.exists():
            self.hub_id = json.loads(hub_file.read_text(encoding="utf-8"))["id"]
        else:
            self.hub_id = secrets.token_hex(16)
            atomic_json(hub_file, {"id": self.hub_id})
        self.db = sqlite3.connect(state_dir / "relay.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (name TEXT PRIMARY KEY, token_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('client','relay')));
            CREATE TABLE IF NOT EXISTS frames (id INTEGER PRIMARY KEY AUTOINCREMENT, destination TEXT NOT NULL, sender TEXT NOT NULL, message_id TEXT NOT NULL, kind TEXT NOT NULL, expires_ms INTEGER NOT NULL, body TEXT NOT NULL, UNIQUE(destination,sender,message_id,kind));
            CREATE INDEX IF NOT EXISTS idx_relay_destination ON frames(destination,id);
        """)
        (state_dir / "relay.db").chmod(0o600)

    def close(self) -> None:
        self.db.close()

    def authorize(self, name: str, *, role: str = "client", token: str | None = None) -> str:
        if role not in {"client", "relay"} or not isinstance(name, str) or not name:
            raise ValueError("Account name and role are required.")
        token = token or secrets.token_urlsafe(32)
        with self._lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO accounts(name,token_hash,role) VALUES(?,?,?)", (name, hashlib.sha256(token.encode()).hexdigest(), role))
        return token

    def authenticate(self, name: str, token: str) -> str:
        with self._lock:
            row = self.db.execute("SELECT token_hash,role FROM accounts WHERE name = ?", (name,)).fetchone()
        if row is None or not hmac.compare_digest(row["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
            raise FaspError("auth.relay_denied", "Relay account or token is invalid.")
        return row["role"]

    def _prune(self) -> None:
        self.db.execute("DELETE FROM frames WHERE expires_ms <= ?", (int(time.time() * 1000),))

    def routes(self) -> dict[str, Any]:
        path = self.state_dir / "routes.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def set_route(self, destination: str, url: str, account: str, token_file: Path, ca_cert: str | None = None) -> None:
        from .relay_wire import check_relay_url

        check_relay_url(url)
        routes = self.routes()
        routes[destination] = {"url": url.rstrip("/"), "account": account, "token_file": str(token_file.resolve()), "ca_cert": ca_cert}
        atomic_json(self.state_dir / "routes.json", routes)

    def accept(self, frame: dict[str, Any], path: list[str], *, actor: str, role: str) -> dict[str, Any]:
        raw = json.dumps(frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_FRAME_BYTES or not isinstance(frame, dict):
            raise FaspError("resource.too_large", "Relay frame exceeds 96 KiB.")
        if not isinstance(path, list) or len(path) >= MAX_HOPS or any(not isinstance(item, str) for item in path) or self.hub_id in path:
            raise FaspError("transport.relay_loop", "Relay hop limit or loop detected.")
        if frame.get("version") != 1 or frame.get("kind") not in {"request", "response"}:
            raise FaspError("schema.invalid", "Unsupported relay frame.")
        sender, destination, message_id = frame.get("from"), frame.get("to"), frame.get("message_id")
        if any(not isinstance(item, str) or not item or len(item) > 128 for item in (sender, destination, message_id)):
            raise FaspError("schema.invalid", "Relay frame IDs are invalid.")
        if role == "client" and actor != sender:
            raise FaspError("auth.relay_denied", "Client may only send as its own identity.")
        from ..timestamps import parse_stamp

        try:
            expires_ms = int(parse_stamp(frame["expires_at"]).timestamp() * 1000)
        except (KeyError, TypeError, ValueError) as exc:
            raise FaspError("schema.invalid", "Relay frame expiry is invalid.") from exc
        now_ms = int(time.time() * 1000)
        if expires_ms <= now_ms or expires_ms > now_ms + MAX_TTL_SECONDS * 1000:
            raise FaspError("schema.invalid", "Relay frame expiry must be within two minutes.")
        with self._lock:
            local = self.db.execute("SELECT role FROM accounts WHERE name = ?", (destination,)).fetchone()
        if local is not None and local["role"] == "client":
            with self._lock, self.db:
                self._prune()
                existing = self.db.execute("SELECT id,body FROM frames WHERE destination=? AND sender=? AND message_id=? AND kind=?", (destination, sender, message_id, frame["kind"])).fetchone()
                if existing is not None:
                    if existing["body"] != raw.decode():
                        # A retry may use a new ephemeral encryption key;
                        # keep the first valid frame until it is consumed.
                        return {"ok": True, "queued": True, "duplicate": True}
                    return {"ok": True, "queued": True, "duplicate": True}
                count = self.db.execute("SELECT COUNT(*) FROM frames WHERE destination = ?", (destination,)).fetchone()[0]
                if count >= MAX_MAILBOX:
                    raise FaspError("resource.exhausted", "Destination relay mailbox is full.")
                total = self.db.execute("SELECT COUNT(*) FROM frames").fetchone()[0]
                if total >= MAX_TOTAL_FRAMES:
                    raise FaspError("resource.exhausted", "Relay storage capacity is full.")
                self.db.execute("INSERT INTO frames(destination,sender,message_id,kind,expires_ms,body) VALUES(?,?,?,?,?,?)", (destination, sender, message_id, frame["kind"], expires_ms, raw.decode()))
            return {"ok": True, "queued": True}
        route = self.routes().get(destination)
        if not isinstance(route, dict):
            raise FaspError("transport.no_route", "No local mailbox or configured next hop for destination.")
        token = Path(route["token_file"]).read_text(encoding="utf-8").strip()
        return relay_http(route["url"], route["account"], token, "POST", "/relay/v1/messages", {"frame": frame, "path": [*path, self.hub_id]}, ca_cert=route.get("ca_cert"))

    def poll(self, destination: str, limit: int = 16) -> list[dict[str, Any]]:
        if not 1 <= limit <= 16:
            raise FaspError("schema.invalid", "Relay poll limit must be 1..16.")
        with self._lock, self.db:
            self._prune()
            rows = self.db.execute("SELECT id,body FROM frames WHERE destination=? ORDER BY id LIMIT ?", (destination, limit)).fetchall()
        return [{"id": row["id"], "frame": json.loads(row["body"])} for row in rows]

    def ack(self, destination: str, frame_id: int) -> None:
        with self._lock, self.db:
            self.db.execute("DELETE FROM frames WHERE destination=? AND id=?", (destination, frame_id))


def create_relay_app(hub: RelayHub) -> Starlette:
    def auth(request: Request) -> tuple[str, str]:
        name = request.headers.get("X-FASP-Relay-Account", "")
        authorization = request.headers.get("Authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        return name, hub.authenticate(name, token)

    async def handle(request: Request) -> JSONResponse:
        try:
            name, role = auth(request)
            if request.method == "GET":
                if role != "client":
                    raise FaspError("auth.relay_denied", "Only clients can poll mailboxes.")
                result = {"frames": hub.poll(name, int(request.query_params.get("limit", "16")))}
            else:
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_FRAME_BYTES + 2048:
                        raise FaspError("resource.too_large", "Relay request body too large.")
                    body.extend(chunk)
                payload = json.loads(body)
                if request.url.path.endswith("/ack"):
                    if role != "client" or not isinstance(payload.get("id"), int):
                        raise FaspError("auth.relay_denied", "Only clients can acknowledge their frames.")
                    hub.ack(name, payload["id"])
                    result = {"ok": True}
                else:
                    result = hub.accept(payload["frame"], payload.get("path", []), actor=name, role=role)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except (FaspError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            code = exc.code if isinstance(exc, FaspError) else "schema.invalid"
            detail = exc.detail if isinstance(exc, FaspError) else "Invalid relay request."
            status = 401 if code.startswith("auth.") else 429 if code == "resource.exhausted" else 503 if code.startswith("transport.") else 400
            return JSONResponse({"error": {"code": code, "detail": detail}}, status_code=status, headers={"Cache-Control": "no-store"})

    return Starlette(routes=[Route("/relay/v1/messages", handle, methods=["GET", "POST"]), Route("/relay/v1/ack", handle, methods=["POST"])])
