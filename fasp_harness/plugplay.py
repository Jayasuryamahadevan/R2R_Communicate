"""Human-friendly FASP onboarding and a deliberately narrow peer/task client.

This module is a CLI and MCP integration boundary, NOT an autonomous planner.
A peer must be confirmed on *each* machine before a task can be sent.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

from .core import FaspError, FaspHarness, JsonState, verify

DEFAULT_STATE = Path(".fasp")
DEFAULT_CAPABILITIES = ("observe.system.status.v1", "coordinate.chat.v1")


def config_for(state_dir: Path) -> dict:
    return JsonState(state_dir).get("node_config.json", {"name": "r2r-node", "public_url": "http://127.0.0.1:8766"})


def open_node(state_dir: Path) -> FaspHarness:
    config = config_for(state_dir)
    return FaspHarness(state_dir, config["name"], config["public_url"])


def _check_url(url: str, allow_insecure: bool) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Expected a plain http(s) endpoint URL without user info, query or fragment.")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"} and not allow_insecure:
        raise ValueError("Remote HTTP is disabled. Configure HTTPS, or use --insecure-http ONLY on an isolated development LAN.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Provide the origin (scheme://host:port), not an endpoint path.")
    return url.rstrip("/")


class _NoRedirect:
    """Avoid silently moving a signed request or private profile to a different origin."""

    def __init__(self) -> None:
        from urllib.request import HTTPRedirectHandler, build_opener
        class BlockRedirects(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError("HTTP redirects are not followed by R2R.")
        self.opener = build_opener(BlockRedirects())

    def json(self, url: str, payload: dict | None = None, *, allow_insecure: bool = False) -> dict:
        parsed = urlsplit(url)
        _check_url(f"{parsed.scheme}://{parsed.netloc}", allow_insecure)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(url, data=body, headers={"Content-Type": "application/json"} if body is not None else {}, method="POST" if body is not None else "GET")
        try:
            with self.opener.open(request, timeout=10) as response:
                if response.status != 200:
                    raise ValueError(f"Remote endpoint returned HTTP {response.status}")
                raw = response.read(65537)
        except HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise ValueError(f"Remote endpoint rejected request (HTTP {exc.code}): {detail}") from exc
        except URLError as exc:
            raise ValueError(f"Could not reach remote node: {exc.reason}") from exc
        if len(raw) > 65536:
            raise ValueError("Remote response exceeds 64 KiB.")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object from remote node.")
        return value


HTTP = _NoRedirect()


def resolve_peer(node: FaspHarness, value: str) -> tuple[str, dict]:
    matched = [(peer_id, peer) for peer_id, peer in node.peers.all().items() if peer_id == value or peer_id.startswith(value) or peer["card"].get("display_name") == value]
    if len(matched) != 1:
        raise ValueError(f"Peer {value!r} was not found or was ambiguous; run 'r2r peers'.")
    return matched[0]


def paired_peer(node: FaspHarness, value: str) -> tuple[str, dict]:
    peer_id, _ = resolve_peer(node, value)
    return peer_id, node._peer(peer_id)  # Also checks revocation and pairing expiry.


def connect(node: FaspHarness, origin: str, *, allow_insecure: bool = False, http=HTTP) -> dict:
    origin = _check_url(origin, allow_insecure)
    remote_card = http.json(origin + "/profile", allow_insecure=allow_insecure)
    FaspHarness.verify_id_card(remote_card)
    if remote_card["system_id"] == node.identity.system_id:
        raise ValueError("Cannot connect a node to its own identity.")
    # Both nodes are still pending after hello. Operators approve independently.
    local_hello = node.hello(remote_card)
    reply = http.json(origin + "/pair/hello", {"id_card": node.id_card()}, allow_insecure=allow_insecure)
    if not isinstance(reply.get("id_card"), dict):
        raise ValueError("Remote hello is missing its signed ID card.")
    FaspHarness.verify_id_card(reply["id_card"])
    if reply["id_card"]["system_id"] != remote_card["system_id"]:
        raise ValueError("Remote identity changed during pairing.")
    verify(reply, remote_card["public_key"])
    if reply.get("system_id") != remote_card["system_id"] or reply.get("pair_code") != local_hello["pair_code"]:
        raise ValueError("Pairing code does not match; do not approve either peer.")
    return {"peer_id": remote_card["system_id"], "peer_name": remote_card.get("display_name"), "our_id": node.identity.system_id, "pair_code": reply["pair_code"]}


def send(node: FaspHarness, peer: str, kind: str, payload: dict, *, allow_insecure: bool = False, http=HTTP) -> dict:
    peer_id, record = paired_peer(node, peer)
    card = record["card"]
    FaspHarness.verify_id_card(card)
    endpoint = card["endpoints"].get("envelopes")
    if not isinstance(endpoint, str):
        raise ValueError("Paired peer does not advertise an envelope endpoint.")
    parsed = urlsplit(endpoint)
    _check_url(f"{parsed.scheme}://{parsed.netloc}", allow_insecure)
    envelope = node.make_envelope(kind, peer_id, payload)
    response = http.json(endpoint, envelope, allow_insecure=allow_insecure)
    if response.get("type") == "receipt.delivered":
        return response.get("response") or {}
    if response.get("type") == "protocol.error":
        raise ValueError(f"Remote policy rejected request: {response.get('error')}")
    return response


def peer_summary(node: FaspHarness) -> list[dict]:
    return [
        {"name": peer["card"].get("display_name"), "id": peer_id, "state": peer["state"],
         "capabilities": [cap["id"] if isinstance(cap, dict) else cap for cap in peer["card"].get("capabilities", [])]}
        for peer_id, peer in node.peers.all().items()
    ]


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="r2r", description="Easy onboarding for the FASP coordination protocol.")
    sub = parser.add_subparsers(dest="command", required=True)
    def add(name: str, description: str):
        p = sub.add_parser(name, help=description)
        p.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
        return p
    p = add("init", "Create a local cryptographic identity and configuration.")
    p.add_argument("--name", default="r2r-node")
    p.add_argument("--public-url", default="http://127.0.0.1:8766", help="Reachable URL advertised by this node.")
    add("peers", "List pending and paired systems and their capabilities.")
    p = add("connect", "Begin two-sided pairing with a remote node.")
    p.add_argument("url")
    p.add_argument("--insecure-http", action="store_true", help="Development LAN only; never use on the public Internet.")
    p = add("approve", "Confirm a peer after comparing the code on both machines.")
    p.add_argument("peer")
    p.add_argument("code")
    p.add_argument("--capability-prefix", action="append", default=None, help="Restrict authorization to a capability prefix; repeatable.")
    p = add("ask", "Send a bounded goal to a paired peer.")
    p.add_argument("peer")
    p.add_argument("objective")
    p.add_argument("--capability", default="coordinate.chat.v1")
    p.add_argument("--idempotency-key", default=None)
    p.add_argument("--insecure-http", action="store_true")
    p = add("status", "Read the status of a previously submitted task.")
    p.add_argument("peer")
    p.add_argument("idempotency_key")
    p.add_argument("--insecure-http", action="store_true")
    p = add("doctor", "Show identity and paired-peer readiness.")
    p = add("mcp", "Serve narrow R2R tools to a local MCP host (stdio).")
    p.add_argument("--allow-capability", action="append", default=[], help="Exact extra task capability exposed to the MCP host.")
    p.add_argument("--insecure-http", action="store_true", help="Development LAN only.")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        from .transport import asgi_server
        old = sys.argv
        try:
            sys.argv = ["r2r", *argv]
            asgi_server.main()
        finally:
            sys.argv = old
        return 0
    args = create_parser().parse_args(argv)
    node: FaspHarness | None = None
    try:
        if args.command == "init":
            config = {"name": args.name, "public_url": _check_url(args.public_url, True)}
            JsonState(args.state_dir).put("node_config.json", config)
        node = open_node(args.state_dir)
        if args.command == "init":
            print(f"Initialized {node.display_name}\nIdentity: {node.identity.system_id}\nState: {args.state_dir}\nNext: r2r serve --name {node.display_name} --state-dir {args.state_dir} --public-url {node.base_url}")
        elif args.command == "peers":
            print(json.dumps(peer_summary(node), indent=2))
        elif args.command == "connect":
            result = connect(node, args.url, allow_insecure=args.insecure_http)
            print(json.dumps(result, indent=2))
            print("Compare the pairing code on BOTH computers. On each computer run:")
            print("  r2r peers")
            print("  r2r approve <other-system-id> <pair-code>")
            print("Pairing on only one computer is not sufficient for bidirectional tasks.")
        elif args.command == "approve":
            peer_id, _ = resolve_peer(node, args.peer)
            print(json.dumps(node.confirm_peer(peer_id, args.code, args.capability_prefix), indent=2))
        elif args.command == "ask":
            key = args.idempotency_key or ("task-" + secrets.token_hex(8))
            result = send(node, args.peer, "intent.propose", {"intent_id": key, "idempotency_key": key, "capability": args.capability, "objective": args.objective}, allow_insecure=args.insecure_http)
            print(json.dumps({"idempotency_key": key, "response": result}, indent=2))
        elif args.command == "status":
            print(json.dumps(send(node, args.peer, "task.status", {"idempotency_key": args.idempotency_key}, allow_insecure=args.insecure_http), indent=2))
        elif args.command == "doctor":
            print(json.dumps({"system_id": node.identity.system_id, "name": node.display_name, "public_url": node.base_url,
                              "audit_valid": node.audit.verify()[0], "peers": peer_summary(node)}, indent=2))
        elif args.command == "mcp":
            from .mcp_gateway import run_mcp
            run_mcp(node, allow_capabilities=set(DEFAULT_CAPABILITIES) | set(args.allow_capability), allow_insecure=args.insecure_http)
        return 0
    except (FaspError, ValueError, OSError) as exc:
        print(f"r2r: {exc}", file=sys.stderr)
        return 2
    finally:
        if node is not None:
            node.close()


if __name__ == "__main__":
    raise SystemExit(main())
