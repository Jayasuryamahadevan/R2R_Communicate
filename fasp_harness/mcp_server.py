"""Local stdio MCP tools over the existing FASP identity and durable outbox.

The SDK is an optional dependency. No MCP HTTP listener or new trust path is
created: the MCP host starts this process with access to one local state dir.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from .agent_cli import _agent, _deliver, connect_device, disconnect_device, inspect_device, ping_device, scan_devices
from .core import MAX_INLINE_BYTES
from .edge.outbox import Outbox
from .protocol.errors import FaspError


def build_server(args: argparse.Namespace) -> Any:
    try:
        from mcp.server import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError
    except ImportError as exc:
        raise RuntimeError("MCP support is optional. Install with: pip install 'fasp-harness[mcp]' (or ./install.sh --with-mcp).") from exc

    server = MCPServer("FASP")

    def enqueue_intent(h: Any, peer_id: str, message: str, capability: str, idempotency_key: str | None, grant_id: str | None) -> dict[str, Any]:
        h._peer(peer_id)
        payload: dict[str, Any] = {"objective": message, "capability": capability, "idempotency_key": idempotency_key or str(uuid.uuid4())}
        if grant_id:
            payload["grant"] = {"id": grant_id}
        envelope = h.make_envelope("intent.propose", peer_id, payload)
        if len(json.dumps(envelope, ensure_ascii=False).encode("utf-8")) > MAX_INLINE_BYTES:
            raise FaspError("resource.too_large", "Signed intent exceeds 64 KiB.")
        queued = Outbox(h.db).enqueue(peer_id, envelope)
        return {"state": "queued", "message_id": queued.message_id, "idempotency_key": payload["idempotency_key"], "expires_at": envelope["expires_at"]}

    @server.tool()
    async def identity() -> dict[str, Any]:
        """Return this node's public signed identity card (no private key or token)."""
        with _agent(args) as h:
            return h.id_card()

    @server.tool()
    async def peers() -> dict[str, Any]:
        """List pinned peer IDs, pairing state, scopes, and configured endpoints."""
        with _agent(args) as h:
            urls = h.state.get("agent-peers.json", {})
            radios = h.state.get("agent-radios.json", {})
            entries = [
                {
                    "peer_id": peer_id,
                    "name": entry["card"].get("display_name"),
                    "state": entry["state"],
                    "expires_at": entry["expires_at"],
                    "scopes": entry["allowed_capability_prefixes"],
                    "url": urls.get(peer_id),
                    "radio": radios.get(peer_id),
                }
                for peer_id, entry in sorted(h.peers.all().items())
            ]
            return {"peers": entries}


    @server.tool()
    async def scan(cidr: str, port: int = 8766, scheme: str = "https", timeout: float = 0.35, workers: int = 16) -> dict[str, Any]:
        """Scan an EXPLICIT operator-authorized private/local CIDR for signed FASP nodes. Never automatically pair; limited to 1024 hosts."""
        def action() -> dict[str, Any]:
            with _agent(args) as h:
                return scan_devices(h, cidr, port, scheme, timeout, workers, args)
        try:
            return await asyncio.to_thread(action)
        except (FaspError, ValueError) as exc:
            raise ToolError(f"{exc.code}: {exc.detail}" if isinstance(exc, FaspError) else str(exc)) from exc

    @server.tool()
    async def inspect(reference: str) -> dict[str, Any]:
        """Check the live signed FASP card for one HTTPS URL or exact discovered/registered system ID; read-only."""
        def action() -> dict[str, Any]:
            with _agent(args) as h:
                return inspect_device(h, reference, args)
        try:
            return await asyncio.to_thread(action)
        except (FaspError, ValueError, OSError) as exc:
            raise ToolError(f"{exc.code}: {exc.detail}" if isinstance(exc, FaspError) else str(exc)) from exc

    @server.tool()
    async def connect(reference: str) -> dict[str, Any]:
        """Start pending FASP pairing. Requires explicit out-of-band fingerprint verification and approval ON BOTH devices."""
        def action() -> dict[str, Any]:
            with _agent(args) as h:
                return connect_device(h, reference, args)
        try:
            return await asyncio.to_thread(action)
        except (FaspError, ValueError, OSError) as exc:
            raise ToolError(f"{exc.code}: {exc.detail}" if isinstance(exc, FaspError) else str(exc)) from exc

    @server.tool()
    async def approve(peer_id: str, pair_code: str, scopes: list[str]) -> dict[str, Any]:
        """ADMIN ACTION: Approve ONE pending peer locally only after an operator verifies the fingerprint independently. Empty scopes deny all capabilities."""
        def action() -> dict[str, Any]:
            if not isinstance(scopes, list) or any(not isinstance(item, str) or not item or "*" in item for item in scopes):
                raise FaspError("schema.invalid", "Explicit scopes must be a list of nonempty capability names without wildcard.")
            with _agent(args) as h:
                return h.confirm_peer(peer_id, pair_code, scopes)
        try:
            return await asyncio.to_thread(action)
        except FaspError as exc:
            raise ToolError(f"{exc.code}: {exc.detail}") from exc

    @server.tool()
    async def disconnect(peer_id: str, reason: str = "operator disconnected peer") -> dict[str, Any]:
        """ADMIN ACTION: Revoke one known peer locally. Does not alter the remote node; re-pairing is required."""
        def action() -> dict[str, Any]:
            with _agent(args) as h:
                return disconnect_device(h, peer_id, reason)
        try:
            return await asyncio.to_thread(action)
        except FaspError as exc:
            raise ToolError(f"{exc.code}: {exc.detail}") from exc

    @server.tool()
    async def capabilities(reference: str | None = None) -> dict[str, Any]:
        """Read this node's declared capabilities or a verified remote device's published capabilities; self-signature is not pairing."""
        def action() -> dict[str, Any]:
            with _agent(args) as h:
                if reference is None:
                    card = h.id_card()
                    return {"peer_id": card["system_id"], "name": card["display_name"], "trusted": True, "capabilities": card["capabilities"]}
                info = inspect_device(h, reference, args)
                return {key: info[key] for key in ("peer_id", "name", "trusted", "state", "capabilities")}
        try:
            return await asyncio.to_thread(action)
        except (FaspError, ValueError, OSError) as exc:
            raise ToolError(f"{exc.code}: {exc.detail}" if isinstance(exc, FaspError) else str(exc)) from exc

    @server.tool()
    async def ping(peer_id: str) -> dict[str, Any]:
        """Send a signed FASP heartbeat to an already paired peer; a network port alone never authenticates a node."""
        def action() -> dict[str, Any]:
            with _agent(args) as h:
                return ping_device(h, peer_id, args)
        try:
            return await asyncio.to_thread(action)
        except (FaspError, ValueError, OSError) as exc:
            raise ToolError(f"{exc.code}: {exc.detail}" if isinstance(exc, FaspError) else str(exc)) from exc

    @server.tool()
    async def outbox(message_id: str | None = None) -> dict[str, Any]:
        """Inspect queued delivery depth or a specific message's saved result."""
        with _agent(args) as h:
            queue = Outbox(h.db)
            if message_id:
                record = queue.get(message_id)
                if record is None:
                    raise ToolError("Unknown outgoing message ID.")
                return record
            return {"depth": queue.depth(), "dead_letters": queue.dead_letters(limit=25)}

    @server.tool()
    async def queue_intent(peer_id: str, message: str, capability: str = "coordinate.chat.v1", idempotency_key: str | None = None, grant_id: str | None = None) -> dict[str, Any]:
        """Sign and durably queue an intent for an already paired peer. Call drain to send it."""
        try:
            with _agent(args) as h:
                return enqueue_intent(h, peer_id, message, capability, idempotency_key, grant_id)
        except FaspError as exc:
            raise ToolError(f"{exc.code}: {exc.detail}") from exc

    @server.tool()
    async def communicate(peer_id: str, message: str, capability: str = "coordinate.chat.v1", idempotency_key: str | None = None, grant_id: str | None = None) -> dict[str, Any]:
        """Queue a signed intent, attempt delivery once, and report its saved delivery state."""
        def send_once() -> dict[str, Any]:
            with _agent(args) as h:
                queued = enqueue_intent(h, peer_id, message, capability, idempotency_key, grant_id)
                _deliver(h, args)
                record = Outbox(h.db).get(queued["message_id"])
                if record is None:
                    raise ToolError("Queued intent disappeared from the outbox.")
                return {
                    **queued,
                    "state": record["state"],
                    "response": record["response"],
                    "last_error": record["last_error"],
                }
        try:
            return await asyncio.to_thread(send_once)
        except FaspError as exc:
            raise ToolError(f"{exc.code}: {exc.detail}") from exc

    @server.tool()
    async def drain() -> dict[str, Any]:
        """Attempt one bounded delivery batch using the registered HTTPS or Bluetooth endpoint."""
        def drain_once() -> dict[str, Any]:
            with _agent(args) as h:
                return _deliver(h, args)

        try:
            return await asyncio.to_thread(drain_once)
        except FaspError as exc:
            raise ToolError(f"{exc.code}: {exc.detail}") from exc

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fasp mcp", description="Local FASP MCP server over stdio.")
    parser.add_argument("--state-dir", default="~/.fasp-agent", help="Existing initialized FASP state directory.")
    parser.add_argument("--ca-cert", help="Custom TLS CA certificate bundle.")
    parser.add_argument("--client-cert", help="mTLS client certificate.")
    parser.add_argument("--client-key", help="mTLS client key.")
    parser.add_argument("--insecure-http", action="store_true", help="Allow remote HTTP only on an isolated development network.")
    args = parser.parse_args(argv)
    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert")
    args.state_dir = str(Path(args.state_dir).expanduser().resolve())
    if not (Path(args.state_dir) / "identity.json").is_file():
        parser.error("State is not initialized. Run: fasp init --name NAME --state-dir PATH")
    args.timeout = 5.0
    args.limit = 16
    args.transport = "auto"
    try:
        server = build_server(args)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
