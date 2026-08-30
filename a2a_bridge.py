#!/usr/bin/env python3
"""A small, dependency-free LAN message bridge for two local AI agents.

It relays text only.  It deliberately does not execute commands received over
the network: each agent remains responsible for deciding what to do with a
message.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DATA = ROOT / ".a2a_bridge"
TOKEN_FILE = DATA / "token"
MESSAGES_FILE = DATA / "messages.jsonl"
RECEIPTS_FILE = DATA / "receipts.json"
PRESENCE_FILE = DATA / "presence.json"
LOCK = threading.RLock()


def token() -> str:
    DATA.mkdir(mode=0o700, exist_ok=True)
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(value + "\n", encoding="utf-8")
    os.chmod(TOKEN_FILE, 0o600)
    return value


def read_messages() -> list[dict]:
    if not MESSAGES_FILE.exists():
        return []
    with LOCK, MESSAGES_FILE.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def read_json_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def write_json_state(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def decorate_messages(messages: list[dict], receipts: dict) -> list[dict]:
    result = []
    for message in messages:
        copy = dict(message)
        copy["delivery"] = receipts.get(message["id"], {"delivered": {}, "read": {}})
        result.append(copy)
    return result


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "A2ABridge/1.0"

    def log_message(self, format: str, *args: object) -> None:
        # Avoid placing message contents or tokens in terminal logs.
        print(f"{self.address_string()} {format % args}")

    def send_json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: Path) -> None:
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def authorised(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-A2A-Token", ""), token())

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(HTTPStatus.OK, {"ok": True, "service": "a2a-lan-bridge"})
            return
        if parsed.path in {"/", "/chat", "/chat/"}:
            self.send_file(ROOT / "a2a_chat.html")
            return
        if parsed.path not in {"/v1/messages", "/v1/transcript", "/v1/presence"}:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self.authorised():
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid X-A2A-Token"})
            return
        if parsed.path == "/v1/presence":
            now = time.time()
            with LOCK:
                presence = read_json_state(PRESENCE_FILE)
                active = {agent: info for agent, info in presence.items() if info.get("expires", 0) > now}
                if active != presence:
                    write_json_state(PRESENCE_FILE, active)
            self.send_json(HTTPStatus.OK, {"presence": active, "server_time": now})
            return
        query = parse_qs(parsed.query)
        try:
            after = float(query.get("after", ["0"])[0])
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "after must be a number"})
            return
        if parsed.path == "/v1/transcript":
            with LOCK:
                messages = [m for m in read_messages() if m["timestamp"] > after]
                receipts = read_json_state(RECEIPTS_FILE)
            self.send_json(HTTPStatus.OK, {"messages": decorate_messages(messages, receipts), "server_time": time.time()})
            return
        recipient = query.get("for", [""])[0].strip()
        if not recipient:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "for is required"})
            return
        with LOCK:
            messages = [m for m in read_messages() if m["to"] == recipient and m["timestamp"] > after]
            receipts = read_json_state(RECEIPTS_FILE)
            now = time.time()
            for message in messages:
                receipts.setdefault(message["id"], {"delivered": {}, "read": {}})["delivered"].setdefault(recipient, now)
            write_json_state(RECEIPTS_FILE, receipts)
        self.send_json(HTTPStatus.OK, {"messages": decorate_messages(messages, receipts), "server_time": now})

    def do_POST(self) -> None:  # noqa: N802
        endpoint = urlparse(self.path).path
        if endpoint not in {"/v1/messages", "/v1/receipts", "/v1/presence"}:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self.authorised():
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid X-A2A-Token"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 16_384:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            if endpoint == "/v1/presence":
                agent, status = payload.get("agent", "").strip(), payload.get("status", "").strip()
                if not agent or len(agent) > 64 or status not in {"online", "typing", "idle"}:
                    raise ValueError
                with LOCK:
                    presence = read_json_state(PRESENCE_FILE)
                    presence[agent] = {"status": status, "updated": time.time(), "expires": time.time() + 15}
                    write_json_state(PRESENCE_FILE, presence)
                self.send_json(HTTPStatus.OK, {"ok": True})
                return
            if endpoint == "/v1/receipts":
                message_id, agent = payload.get("message_id", "").strip(), payload.get("agent", "").strip()
                if not message_id or not agent or payload.get("status") != "read":
                    raise ValueError
                with LOCK:
                    receipts = read_json_state(RECEIPTS_FILE)
                    receipts.setdefault(message_id, {"delivered": {}, "read": {}})["read"][agent] = time.time()
                    write_json_state(RECEIPTS_FILE, receipts)
                self.send_json(HTTPStatus.OK, {"ok": True})
                return
            sender, recipient, text = (payload.get(key, "").strip() for key in ("from", "to", "text"))
            if not sender or not recipient or not text or len(sender) > 64 or len(recipient) > 64 or len(text) > 12_000:
                raise ValueError
        except (ValueError, json.JSONDecodeError, AttributeError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "send JSON: from, to, text"})
            return
        message = {"id": str(uuid.uuid4()), "from": sender, "to": recipient, "text": text, "timestamp": time.time()}
        with LOCK, MESSAGES_FILE.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.send_json(HTTPStatus.CREATED, {"ok": True, "message": message})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a text-only A2A bridge on your LAN.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--show-token", action="store_true")
    args = parser.parse_args()
    value = token()
    if args.show_token:
        print(value)
        return
    server = ThreadingHTTPServer((args.host, args.port), BridgeHandler)
    print(f"A2A LAN bridge listening on http://{args.host}:{args.port}")
    print("Token exists at .a2a_bridge/token (share it only with your phone).")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBridge stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
