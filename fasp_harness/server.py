"""HTTP baseline profile for the FASP harness."""

from __future__ import annotations

import argparse
import importlib
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .core import FaspError, FaspHarness


def load_adapter(reference: str | None) -> object | None:
    """Load a local model adapter as module:object or module:factory."""
    if not reference:
        return None
    try:
        module_name, object_name = reference.split(":", 1)
        candidate = getattr(importlib.import_module(module_name), object_name)
        adapter = candidate() if callable(candidate) and not hasattr(candidate, "handle") else candidate
        if not callable(getattr(adapter, "capabilities", None)) or not callable(getattr(adapter, "handle", None)):
            raise TypeError("adapter must provide capabilities() and handle(intent)")
        return adapter
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise SystemExit(f"Cannot load --adapter {reference!r}: {exc}") from exc


class FaspHTTPServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], harness: FaspHarness) -> None:
        super().__init__(address, FaspHandler)
        self.harness = harness


class FaspHandler(BaseHTTPRequestHandler):
    server: FaspHTTPServer
    server_version = "FASP-Harness/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        # Never log message bodies, tokens, or signatures.
        print(f"{self.address_string()} {fmt % args}")

    def _json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, error: FaspError) -> None:
        status = HTTPStatus.BAD_REQUEST
        if error.code.startswith("auth."):
            status = HTTPStatus.UNAUTHORIZED
        elif error.code in {"capability.unavailable", "protocol.unsupported_kind"}:
            status = HTTPStatus.NOT_FOUND
        elif error.code in {"resource.too_large", "resource.exhausted"}:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        self._json(status, {"fasp": "fasp/1.0", "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}})

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 64 * 1024:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (ValueError, json.JSONDecodeError):
            raise FaspError("schema.invalid", "Body must be a JSON object smaller than 64 KiB.") from None

    def _admin(self) -> None:
        presented = self.headers.get("X-FASP-Admin-Token", "")
        if presented != self.server.harness.admin_token:
            raise FaspError("auth.admin_required", "Local administrator token is required.")

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        try:
            if route in {"/id_card", "/.well-known/fasp/id-card.json"}:
                self._json(HTTPStatus.OK, self.server.harness.id_card())
            elif route == "/capabilities":
                self._json(HTTPStatus.OK, {"fasp": "fasp/1.0", "system_id": self.server.harness.identity.system_id, "capabilities": self.server.harness.adapter.capabilities()})
            elif route == "/health":
                self._json(HTTPStatus.OK, {"ok": True, "fasp": "fasp/1.0", "system_id": self.server.harness.identity.system_id})
            elif route == "/peers":
                self._admin()
                self._json(HTTPStatus.OK, self.server.harness.state.get("peers.json", {}))
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except FaspError as error:
            self._error(error)

    def do_POST(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        try:
            payload = self._body()
            if route == "/hello":
                self._json(HTTPStatus.OK, self.server.harness.hello(payload.get("id_card", {})))
            elif route == "/pair/confirm":
                self._admin()
                self._json(HTTPStatus.OK, self.server.harness.confirm_peer(payload.get("peer_id", ""), payload.get("pair_code", ""), payload.get("allowed_capability_prefixes")))
            elif route in {"/send", "/task"}:
                duplicate, response = self.server.harness.accept(payload, "intent.propose" if route == "/task" else None)
                self._json(HTTPStatus.OK, {"fasp": "fasp/1.0", "type": "receipt.delivered", "duplicate": duplicate, "message_id": payload.get("message_id"), "response": response})
            elif route == "/inbox":
                self._json(HTTPStatus.OK, self.server.harness.pull_inbox(payload))
            elif route == "/receipt":
                self._json(HTTPStatus.OK, self.server.harness.receipt(payload))
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except FaspError as error:
            self._error(error)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a model-agnostic FASP harness endpoint.")
    parser.add_argument("serve", nargs="?", default="serve")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--name", default="fasp-system")
    parser.add_argument("--state-dir", type=Path, default=Path(".fasp"))
    parser.add_argument("--public-url", help="Advertised HTTPS/HTTP base URL; required for a reachable LAN peer.")
    parser.add_argument("--adapter", help="Optional local model adapter: module:object or module:factory")
    args = parser.parse_args()
    base_url = args.public_url or f"http://{args.host}:{args.port}"
    harness = FaspHarness(args.state_dir, args.name, base_url, load_adapter(args.adapter))
    server = FaspHTTPServer((args.host, args.port), harness)
    print(f"FASP harness for {harness.identity.system_id}")
    print(f"ID card: {base_url}/id_card")
    print(f"Admin token file: {args.state_dir / 'admin_token'} (keep private)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFASP harness stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
