"""Expose paired FASP systems through official MCP Python SDK v2, stdio only.

The MCP host never receives private identity keys or the FASP admin token.
Every task still goes through the receiving node's FASP authorization policy.
"""
from __future__ import annotations

import secrets

from .core import FaspHarness
from .plugplay import peer_summary, paired_peer, send


def build_mcp(node: FaspHarness, *, allow_capabilities: set[str], allow_insecure: bool = False):
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise ValueError("MCP integration is optional: install with 'pip install -e \".[mcp]\"'") from exc

    server = MCPServer("R2R FASP Gateway")
    # Exact capability IDs only, no broad wildcard or arbitrary tool execution.
    approved = frozenset(allow_capabilities)

    @server.tool()
    def r2r_list_peers() -> list[dict]:
        """List locally known R2R systems and advertised capabilities. Pending systems cannot accept tasks."""
        return peer_summary(node)

    @server.tool()
    def r2r_get_capabilities(peer: str) -> list[dict]:
        """Show capabilities advertised by a paired peer; this does not grant permission to execute them."""
        _, record = paired_peer(node, peer)
        FaspHarness.verify_id_card(record["card"])
        return record["card"].get("capabilities", [])

    @server.tool()
    def r2r_send_task(peer: str, capability: str, objective: str) -> dict:
        """Propose a bounded goal to a paired system; only pre-approved capability IDs are exposed to this MCP host."""
        if capability not in approved:
            raise ValueError(f"Capability {capability!r} is not enabled in this MCP gateway. Administrator must add --allow-capability.")
        if not objective or len(objective) > 2000:
            raise ValueError("Goal text must be between 1 and 2000 characters.")
        key = "mcp-" + secrets.token_hex(12)
        result = send(node, peer, "intent.propose", {"intent_id": key, "idempotency_key": key, "capability": capability, "objective": objective}, allow_insecure=allow_insecure)
        return {"idempotency_key": key, "response": result}

    @server.tool()
    def r2r_get_task_status(peer: str, idempotency_key: str) -> dict:
        """Poll a task submitted by this local R2R identity; the remote server enforces task ownership."""
        return send(node, peer, "task.status", {"idempotency_key": idempotency_key}, allow_insecure=allow_insecure)

    return server


def run_mcp(node: FaspHarness, *, allow_capabilities: set[str], allow_insecure: bool = False) -> None:
    # stdio transport only: no remote-facing MCP listener or ambient network admin privileges.
    build_mcp(node, allow_capabilities=allow_capabilities, allow_insecure=allow_insecure).run()
