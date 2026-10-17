"""Agent-oriented CLI: explicit pairing, signed RPCs, and durable delivery.

All wire operations use the existing FASP v1 protocol and trust model.
'register' is a two-sided pending pairing ceremony, NOT automatic trust.
"""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import ipaddress
import json
import math
import os
import re
import secrets
import ssl
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib import error, parse, request

from .crypto.envelope import verify
from .edge.outbox import Outbox
from .protocol.contracts import MAX_RECORD_BYTES as MAX_INLINE_BYTES
from .protocol.contracts import check_peer_features
from .protocol.errors import FaspError
from .timestamps import stamp
from .transport.canonical import decode_object

if TYPE_CHECKING:
    from .core import FaspHarness

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
AGENT_COMMANDS = frozenset({"init", "id", "import-card", "scan", "inspect", "connect", "register", "radio-register", "approve", "disconnect", "peers", "devices", "capabilities", "status", "ping", "communicate", "send", "drain", "outbox", "task-status", "task-reconcile", "route", "say", "speak", "tasks", "task-cancel", "relay-serve", "relay-authorize", "relay-route", "relay-config", "relay-worker"})
ROUTE_PATTERN = re.compile(r"agent(?:\.[a-z][a-z0-9_-]{0,62})+\Z")
_HUMAN_OUTPUT: contextvars.ContextVar[bool] = contextvars.ContextVar("fasp_human_output", default=False)


class RemoteRejection(Exception):
    def __init__(self, code: str, detail: str, status: int) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.status = status


class TransportFailure(Exception):
    pass


def _emit(data: Any) -> None:
    if _HUMAN_OUTPUT.get():
        print(_render_human(data))
    else:
        print(json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _render_human(data: Any) -> str:
    if not isinstance(data, dict):
        return json.dumps(data, ensure_ascii=False, indent=2)
    if "error" in data and not data.get("ok", True):
        error = data["error"]
        return f"Error [{error.get('code', 'cli.error')}]: {error.get('detail', 'Unknown error')}"
    if "pair_code" in data:
        lines = [f"Found {data.get('name') or data['peer_id']}", f"System ID: {data['peer_id']}", f"Pairing code: {data['pair_code']}"]
        if data.get("route"):
            lines.append(f"Local name: {data['route']}")
        lines.append("Compare this code independently, then approve on both systems.")
        return "\n".join(lines)
    if "outbox" in data and isinstance(data.get("peers"), dict):
        peers = data["peers"]
        return f"{data.get('name', 'This system')}  {data['system_id']}\nPeers: {peers.get('paired', 0)} paired, {peers.get('pending', 0)} pending\nOutbox: {data['outbox'].get('pending', 0)} pending, {data['outbox'].get('dead', 0)} dead"
    if "routes" in data:
        return "No local names." if not data["routes"] else "\n".join(f"{route['name']} -> {route['peer_id']}" for route in data["routes"])
    if "name" in data and "peer_id" in data and "removed" in data:
        return f"Removed {data['name']} (was {data['peer_id']})."
    if "name" in data and "peer_id" in data and data.get("ok"):
        return f"{data['name']} -> {data['peer_id']}"
    if "tasks" in data:
        return "No outgoing tasks." if not data["tasks"] else "\n".join(f"{task.get('task_path') or task['idempotency_key']}  {task['state']}  {task['idempotency_key']}" for task in data["tasks"])
    if "peers" in data and isinstance(data["peers"], list):
        return "No known peers." if not data["peers"] else "\n".join(f"{peer.get('name') or peer['peer_id']}  {peer['state']}  {peer['peer_id']}" for peer in data["peers"])
    if "message_id" in data and "state" in data:
        lines = [f"Delivery: {data['state']}", f"Message ID: {data['message_id']}"]
        if data.get("idempotency_key"):
            lines.append(f"Task key: {data['idempotency_key']}")
        response = data.get("response") or {}
        outcome = response.get("response", response) if isinstance(response, dict) else {}
        if isinstance(outcome, dict):
            summary = outcome.get("output", {}).get("summary") if isinstance(outcome.get("output"), dict) else None
            if summary is not None:
                lines.append(f"Reply: {summary}")
        if data["state"] == "pending":
            lines.append("Queued locally. Run 'fasp drain --watch' to retry.")
        return "\n".join(lines)
    if "system_id" in data:
        return f"{data.get('name') or data.get('display_name') or 'This system'}\nSystem ID: {data['system_id']}"
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def _state_dir(args: argparse.Namespace) -> Path:
    return Path(args.state_dir).expanduser().resolve()


def _base_url(url: str, insecure_http: bool) -> str:
    parts = parse.urlsplit(url.rstrip("/"))
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise FaspError("schema.invalid", "Expected an http(s) node URL without credentials or query parameters.")
    try:
        _ = parts.port
    except ValueError as exc:
        raise FaspError("schema.invalid", "Invalid server port.") from exc
    if parts.scheme == "http" and not insecure_http and parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise FaspError("transport.tls_required", "Remote HTTP is refused; use HTTPS or explicitly opt into --insecure-http for development.")
    return url.rstrip("/")


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def request_json(url: str, payload: dict[str, Any] | None, args: argparse.Namespace) -> dict[str, Any]:
    base = _base_url(url, args.insecure_http)
    tls = ssl.create_default_context(cafile=args.ca_cert)
    if args.client_cert:
        tls.load_cert_chain(args.client_cert, args.client_key)
    opener = request.build_opener(request.HTTPSHandler(context=tls), _NoRedirect())
    data = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8") if payload is not None else None
    if data is not None and len(data) > MAX_INLINE_BYTES:
        raise FaspError("resource.too_large", "Request body exceeds 64 KiB.")
    req = request.Request(base, data=data, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST" if payload is not None else "GET")
    try:
        with opener.open(req, timeout=args.timeout) as resp:
            if resp.headers.get("Content-Length") and int(resp.headers["Content-Length"]) > MAX_RESPONSE_BYTES:
                raise TransportFailure("Remote response exceeds size limit.")
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise TransportFailure("Remote response exceeds size limit.")
    except error.HTTPError as exc:
        raw = exc.read(4096)
        try:
            response = json.loads(raw)
            detail = response.get("error", {}) if isinstance(response, dict) else {}
        except (ValueError, UnicodeError):
            detail = {}
        raise RemoteRejection(str(detail.get("code", "transport.http_error")), str(detail.get("detail", "Remote request rejected.")), exc.code) from exc
    except (error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        raise TransportFailure(f"Remote transport unavailable ({type(exc).__name__}).") from exc
    try:
        result = decode_object(body, limit=MAX_RESPONSE_BYTES)
    except FaspError as exc:
        raise TransportFailure("Remote response is not a valid canonical JSON object.") from exc
    if result.get("type") == "protocol.error":
        problem = result.get("error", {})
        raise RemoteRejection(str(problem.get("code", "protocol.error")), str(problem.get("detail", "Rejected.")), 400)
    return result


def _open_agent(args: argparse.Namespace) -> FaspHarness:
    from .core import FaspHarness

    state = _state_dir(args)
    if not (state / "identity.json").is_file():
        raise FaspError("config.not_initialized", "First run: fasp init --name NAME --state-dir PATH")
    config_file = state / "agent.json"
    config = json.loads(config_file.read_text(encoding="utf-8")) if config_file.exists() else {}
    adapter = None
    if getattr(args, "adapter", None):
        from .transport.asgi_server import load_adapter

        adapter = load_adapter(args.adapter)
    return FaspHarness(state, config.get("name", "fasp-agent"), config.get("base_url", "http://127.0.0.1:8766"), adapter=adapter)


@contextlib.contextmanager
def _agent(args: argparse.Namespace) -> Any:
    harness = _open_agent(args)
    try:
        yield harness
    finally:
        harness.close()


@contextlib.contextmanager
def _delivery_lock(state: Path) -> Any:
    """Single active sender per local state directory (POSIX/Windows)."""
    path = state / ".fasp-delivery.lock"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise FaspError("resource.busy", "Another CLI delivery worker owns this state directory.") from exc
            try:
                yield
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise FaspError("resource.busy", "Another CLI delivery worker owns this state directory.") from exc
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _peer_endpoint(harness: FaspHarness, peer_id: str, args: argparse.Namespace, features: list[str] | None = None) -> str:
    pinned = harness._peer(peer_id)
    endpoints = harness.state.get("agent-peers.json", {})
    base = endpoints.get(peer_id)
    if not isinstance(base, str):
        raise FaspError("config.peer_url_missing", "Peer has no registered URL. Run 'fasp register URL' on this node.")
    base = _base_url(base, args.insecure_http)
    card = request_json(base + "/profile", None, args)
    harness.verify_id_card(card)
    if card["system_id"] != peer_id or card["public_key"] != pinned["card"]["public_key"]:
        raise FaspError("auth.peer_identity_changed", "Live service identity differs from the pinned pairing identity.")
    check_peer_features(card, features or [])
    return base + "/fasp/v1/envelopes"


def _radio_endpoint(harness: FaspHarness, peer_id: str):
    from .transport.radio import RadioEndpoint

    endpoints = harness.state.get("agent-radios.json", {})
    if peer_id not in endpoints:
        raise FaspError("config.peer_radio_missing", "Peer has no registered Bluetooth endpoint. Run 'fasp radio-register'.")
    endpoint = RadioEndpoint.from_dict(endpoints[peer_id])
    return endpoint


def _send_to_peer(harness: FaspHarness, peer_id: str, envelope: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    transport = args.transport
    relay_configured = (harness.state.directory / "relay-client.json").is_file()
    if transport == "auto":
        transport = "http" if peer_id in harness.state.get("agent-peers.json", {}) else "relay" if relay_configured else "radio"
    if transport == "http":
        try:
            return request_json(_peer_endpoint(harness, peer_id, args, envelope.get("required_features", [])), envelope, args)
        except TransportFailure:
            if args.transport != "auto":
                raise
            if relay_configured:
                transport = "relay"
            elif peer_id not in harness.state.get("agent-radios.json", {}):
                raise
    if transport == "relay":
        from .transport.relay_client import RelayClient

        return RelayClient(harness, ca_cert=args.ca_cert, timeout=args.timeout).send_request(peer_id, envelope)

    from .transport.radio import request_radio

    endpoint = _radio_endpoint(harness, peer_id)
    card = request_radio(endpoint, {"type": "profile"}, timeout=args.timeout)
    harness.verify_id_card(card)
    pinned = harness._peer(peer_id)
    if card["system_id"] != peer_id or card["public_key"] != pinned["card"]["public_key"]:
        raise FaspError("auth.peer_identity_changed", "Live Bluetooth peer differs from the pinned pairing identity.")
    check_peer_features(card, envelope.get("required_features", []))
    return request_radio(endpoint, {"type": "envelope", "envelope": envelope}, timeout=args.timeout)


def _deliver(harness: FaspHarness, args: argparse.Namespace) -> dict[str, Any]:
    outbox = Outbox(harness.db)
    delivered: list[dict[str, Any]] = []
    retried: list[str] = []
    dead: list[str] = []
    with _delivery_lock(_state_dir(args)):
        outbox.recover_inflight()
        messages = outbox.claim_ready(limit=args.limit)
        for message in messages:
            try:
                response = _send_to_peer(harness, message.destination, message.envelope, args)
                if response.get("type") == "receipt.delivered":
                    if response.get("message_id") != message.message_id:
                        raise TransportFailure("Receipt message ID does not match the signed envelope.")
                    if response.get("response", {}).get("type") == "protocol.error":
                        problem = response["response"]["error"]
                        raise RemoteRejection(str(problem.get("code", "protocol.error")), str(problem.get("detail", "Rejected.")), 400)
                elif message.kind in {"intent.propose", "task.cancel", "artifact.fetch"}:
                    raise TransportFailure("Remote server omitted the required delivery receipt.")
                outbox.mark_sent(message.row_id, response)
                delivered.append({"message_id": message.message_id, "response": response})
            except RemoteRejection as exc:
                if exc.status in {408, 425, 429} or exc.status >= 500:
                    outbox.mark_failed(message.row_id, str(exc))
                    retried.append(message.message_id)
                else:
                    outbox.mark_dead(message.row_id, str(exc), {"error": {"code": exc.code, "detail": exc.detail}})
                    dead.append(message.message_id)
            except FaspError as exc:
                if exc.code in {"resource.exhausted", "transport.unreachable", "transport.response_unavailable"}:
                    outbox.mark_failed(message.row_id, f"{exc.code}: {exc.detail}")
                    retried.append(message.message_id)
                else:
                    outbox.mark_dead(message.row_id, f"{exc.code}: {exc.detail}", {"error": {"code": exc.code, "detail": exc.detail}})
                    dead.append(message.message_id)
            except (TransportFailure, OSError) as exc:
                outbox.mark_failed(message.row_id, str(exc))
                retried.append(message.message_id)
    return {"delivered": delivered, "retry": retried, "dead": dead, "depth": outbox.depth()}


def cmd_init(args: argparse.Namespace) -> int:
    from .core import FaspHarness

    state = _state_dir(args)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_file = state / "agent.json"
    base = _base_url(args.base_url, args.insecure_http)
    if config_file.exists():
        config = json.loads(config_file.read_text(encoding="utf-8"))
        if config != {"name": args.name, "base_url": base}:
            raise FaspError("config.already_initialized", "Agent config exists with different settings; refusing to silently overwrite identity configuration.")
    harness = FaspHarness(state, args.name, base)
    try:
        if not config_file.exists():
            harness.state.put("agent.json", {"name": args.name, "base_url": base})
        _emit({"ok": True, "system_id": harness.identity.system_id, "name": args.name, "state_dir": str(state), "id_card": harness.id_card()})
    finally:
        harness.close()
    return 0


def cmd_id(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(h.id_card())
    return 0


def cmd_import_card(args: argparse.Namespace) -> int:
    with Path(args.file).open("rb") as stream:
        data = stream.read(MAX_INLINE_BYTES + 1)
    if len(data) > MAX_INLINE_BYTES:
        raise FaspError("resource.too_large", "ID card file exceeds 64 KiB.")
    card = decode_object(data, limit=MAX_INLINE_BYTES)
    with _agent(args) as h:
        peer_id = card.get("system_id")
        if args.as_name:
            _check_route_target(h, args.as_name, peer_id)
        hello = h.hello(card)
        route = _bind_route(h, args.as_name, peer_id, allow_pending=True) if args.as_name else None
        _emit({"ok": True, "peer_id": peer_id, "name": card.get("display_name"), "state": _peer_state(h, peer_id), "pair_code": hello["pair_code"], "route": route, "approval_required": True, "instructions": "Verify both system IDs and the pairing code through an independent trusted channel, then approve on both nodes."})
    return 0



def _peer_state(h: FaspHarness, peer_id: str) -> str:
    """A display-only state; never treat discovery as authorization."""
    if h.revocations.is_revoked(peer_id):
        return "revoked"
    peer = h.peers.get(peer_id)
    if peer is None:
        return "discovered"
    if peer["state"] == "paired":
        try:
            h._peer(peer_id)
        except FaspError:
            return "expired"
    return str(peer["state"])


def _route_name(name: str) -> str:
    if not isinstance(name, str) or len(name) > 255 or not ROUTE_PATTERN.fullmatch(name):
        raise FaspError("schema.invalid", "Local names must look like agent.researcher (lowercase dot-separated segments).")
    return name


def _routes(h: FaspHarness) -> dict[str, str]:
    routes = h.state.get("agent-routes.json", {})
    if not isinstance(routes, dict):
        raise FaspError("config.invalid", "Agent routes must be a JSON object.")
    return routes


def _resolve_peer(h: FaspHarness, reference: str) -> str:
    if not reference.startswith("agent."):
        return reference
    name = _route_name(reference)
    peer = _routes(h).get(name)
    if not isinstance(peer, str):
        raise FaspError("config.route_missing", f"No local name {name}; use 'fasp route add'.")
    return peer


def _check_route_target(h: FaspHarness, name: str, peer_id: str) -> str:
    name = _route_name(name)
    existing = _routes(h).get(name)
    if existing is not None and existing != peer_id:
        raise FaspError("config.route_exists", "Name already targets another peer; remove it explicitly first.")
    return name


def _bind_route(h: FaspHarness, name: str, peer_id: str, *, allow_pending: bool = False) -> str:
    if not allow_pending:
        h._peer(peer_id)
    name = _check_route_target(h, name, peer_id)
    routes = _routes(h)
    routes[name] = peer_id
    h.state.put("agent-routes.json", routes)
    return name


def _resolve_task_path(h: FaspHarness, path: str) -> tuple[str, str]:
    path = _route_name(path)
    parents = [name for name in _routes(h) if path.startswith(name + ".")]
    if not parents:
        raise FaspError("config.route_missing", "No parent name for this task path; use 'fasp route add agent.ROLE PEER_ID'.")
    parent = max(parents, key=len)
    return _routes(h)[parent], path[len(parent) + 1 :]


def _resolve_device(h: FaspHarness, reference: str, args: argparse.Namespace) -> tuple[str, str | None, dict[str, Any] | None]:
    """Resolve an explicit URL or an exact ID from local scanned/pinned records."""
    if not isinstance(reference, str) or not reference:
        raise FaspError("schema.invalid", "Device reference must be an HTTPS URL or full FASP system ID.")
    if reference.startswith("agent."):
        reference = _resolve_peer(h, reference)
    if not reference.startswith("fasp:system:"):
        return _base_url(reference, args.insecure_http), None, None

    known = h.state.get("agent-peers.json", {})
    scanned = h.state.get("discovered.json", {})
    candidate = scanned.get(reference)
    if reference in known:
        url = known[reference]
    elif isinstance(candidate, dict):
        address, port = candidate.get("address"), candidate.get("port")
        card = candidate.get("card", {})
        profile = card.get("endpoints", {}).get("profile", "") if isinstance(card, dict) else ""
        scheme = candidate.get("scheme") or parse.urlsplit(profile).scheme
        if not isinstance(address, str) or not isinstance(port, int) or scheme not in {"https", "http"}:
            raise FaspError("schema.invalid", "Scanned device record is malformed; rescan with an explicit CIDR.")
        host = f"[{address}]" if ":" in address else address
        url = f"{scheme}://{host}:{port}"
    else:
        raise FaspError("config.peer_url_missing", "Unknown device ID; run 'fasp scan --cidr NETWORK' or provide an HTTPS URL.")
    if not isinstance(url, str):
        raise FaspError("schema.invalid", "Stored peer URL is invalid.")
    return _base_url(url, args.insecure_http), reference, candidate if isinstance(candidate, dict) else None


def inspect_device(h: FaspHarness, reference: str, args: argparse.Namespace) -> dict[str, Any]:
    """Verify a live card, including existing key pinning and scan-to-connect identity continuity."""
    base, expected, scanned = _resolve_device(h, reference, args)
    card = request_json(base + "/profile", None, args)
    h.verify_id_card(card)
    peer_id = card["system_id"]
    if expected is not None and peer_id != expected:
        raise FaspError("auth.peer_identity_changed", "Endpoint no longer exposes the requested FASP system ID.")
    if scanned is not None and isinstance(scanned.get("card"), dict):
        earlier = scanned["card"]
        if earlier.get("system_id") != peer_id or earlier.get("public_key") != card["public_key"]:
            raise FaspError("auth.peer_identity_changed", "Live identity differs from the signed discovery result.")
    pinned = h.peers.get(peer_id)
    if pinned is not None and pinned["card"]["public_key"] != card["public_key"]:
        raise FaspError("auth.peer_identity_changed", "Live identity differs from the pinned local peer key.")
    if peer_id == h.identity.system_id:
        raise FaspError("auth.self_pairing", "The endpoint is this node; connect another device.")
    state = _peer_state(h, peer_id)
    return {
        "peer_id": peer_id,
        "name": card.get("display_name"),
        "url": base,
        "state": state,
        "trusted": state == "paired",
        "capabilities": card.get("capabilities", []),
        "id_card": card,
    }


def connect_device(h: FaspHarness, reference: str, args: argparse.Namespace) -> dict[str, Any]:
    """Create *pending* bilateral pairing, never authorize without out-of-band approval."""
    info = inspect_device(h, reference, args)
    card = info["id_card"]
    base = info["url"]
    as_name = getattr(args, "as_name", None)
    if as_name:
        _check_route_target(h, as_name, card["system_id"])
    response = request_json(base + "/pair/hello", {"id_card": h.id_card()}, args)
    if response.get("type") != "hello.ready" or response.get("system_id") != card["system_id"]:
        raise FaspError("auth.invalid_hello", "Peer hello did not match the discovered identity.")
    verify(response, card["public_key"])
    response_card = response.get("id_card", {})
    h.verify_id_card(response_card)
    if response_card["system_id"] != card["system_id"] or response_card["public_key"] != card["public_key"]:
        raise FaspError("auth.invalid_hello", "Peer changed identity between discovery and hello.")
    pending = h.hello(response_card)
    if response.get("pair_code") != pending.get("pair_code"):
        raise FaspError("auth.invalid_hello", "Pairing fingerprint differs between peers.")
    urls = h.state.get("agent-peers.json", {})
    urls[card["system_id"]] = base
    h.state.put("agent-peers.json", urls)
    route = _bind_route(h, as_name, card["system_id"], allow_pending=True) if as_name else None
    state = _peer_state(h, card["system_id"])
    return {
        "ok": True,
        "peer_id": card["system_id"],
        "name": card.get("display_name"),
        "state": state,
        "pair_code": pending["pair_code"],
        "route": route,
        "approval_required": state != "paired",
        "instructions": "Verify this fingerprint out of band, confirm the peer identity, and approve on BOTH nodes. Connecting does not grant authority.",
    }


def scan_devices(
    h: FaspHarness, cidr: str, port: int, scheme: str, timeout: float,
    workers: int, args: argparse.Namespace, *, allow_large: bool = False,
) -> dict[str, Any]:
    """Opt-in discovery of FASP-speaking devices on one specified private CIDR."""
    from .discovery import discover

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise FaspError("schema.invalid", "Provide a valid explicit CIDR (for example 192.168.1.0/24).") from exc
    if not (network.is_private or network.is_loopback):
        raise FaspError("policy.discovery_scope", "CIDR discovery is restricted to private/local networks; use 'fasp inspect URL' for a public endpoint.")
    if scheme not in {"https", "http"}:
        raise FaspError("schema.invalid", "Discovery scheme must be https or http.")
    if scheme == "http" and not (args.insecure_http or network.is_loopback):
        raise FaspError("transport.tls_required", "Scanning non-loopback HTTP requires explicit --insecure-http for isolated development.")
    if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise FaspError("schema.invalid", "Scan timeout must be between 0 and 30 seconds.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise FaspError("schema.invalid", "Scan port must be 1..65535.")
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 32:
        raise FaspError("schema.invalid", "Scan workers must be 1..32.")
    results = discover(
        cidr, port, timeout, workers, h.state.directory, allow_large=allow_large,
        scheme=scheme, ca_cert=args.ca_cert,
        client_cert=args.client_cert, client_key=args.client_key,
    )
    devices = []
    for entry in results:
        card = entry["card"]
        peer_id = card["system_id"]
        host = f"[{entry['address']}]" if ":" in entry["address"] else entry["address"]
        devices.append({
            "peer_id": peer_id, "name": card.get("display_name"), "state": _peer_state(h, peer_id),
            "trusted": _peer_state(h, peer_id) == "paired", "url": f"{scheme}://{host}:{port}",
            "capabilities": card.get("capabilities", []),
        })
    return {"cidr": str(network), "count": len(devices), "devices": devices, "note": "Only verified self-signed FASP nodes are listed. Scanning does not pair or authorize."}


def ping_device(h: FaspHarness, peer_id: str, args: argparse.Namespace) -> dict[str, Any]:
    peer_id = _resolve_peer(h, peer_id)
    h._peer(peer_id)
    response = _send_to_peer(h, peer_id, h.make_envelope("heartbeat", peer_id, {}), args)
    if response.get("type") != "heartbeat":
        raise TransportFailure("Peer did not return the expected FASP heartbeat response.")
    return {"ok": True, "peer_id": peer_id, "authenticated": True, "response": response}


def disconnect_device(h: FaspHarness, peer_id: str, reason: str) -> dict[str, Any]:
    peer_id = _resolve_peer(h, peer_id)
    if not h.peers.get(peer_id):
        raise FaspError("auth.pairing_not_found", "Unknown peer; there is no pairing to revoke.")
    if not isinstance(reason, str) or not 1 <= len(reason) <= 200:
        raise FaspError("schema.invalid", "Revocation reason must be 1..200 characters.")
    result = h.revoke_peer(peer_id, reason)
    return {**result, "local_only": True, "note": "This node rejects further requests from the peer. Reconnect requires explicit pairing and approval; remote peer state is unchanged."}


def cmd_scan(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(scan_devices(h, args.cidr, args.port, args.scheme, args.timeout, args.workers, args, allow_large=args.allow_large))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(inspect_device(h, args.reference, args))
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(connect_device(h, args.reference, args))
    return 0


def cmd_disconnect(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(disconnect_device(h, args.peer, args.reason))
    return 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        if args.reference is None:
            card = h.id_card()
            _emit({"peer_id": card["system_id"], "name": card["display_name"], "trusted": True, "capabilities": card["capabilities"]})
        else:
            info = inspect_device(h, args.reference, args)
            _emit({key: info[key] for key in ("peer_id", "name", "trusted", "state", "capabilities")})
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        peers = h.peers.all()
        _emit({
            "system_id": h.identity.system_id, "name": h.display_name,
            "capabilities": h.adapter.capabilities(),
            "peers": {state: sum(_peer_state(h, peer_id) == state for peer_id in peers) for state in ("paired", "pending", "expired", "revoked")},
            "outbox": Outbox(h.db).depth(),
        })
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(ping_device(h, args.peer, args))
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    """Compatibility alias for 'connect' with an explicit HTTPS URL."""
    with _agent(args) as h:
        _emit(connect_device(h, args.url, args))
    return 0


def cmd_radio_register(args: argparse.Namespace) -> int:
    from .transport.radio import RadioEndpoint, request_radio

    endpoint = RadioEndpoint(args.mode, args.address, channel=args.channel, psm=args.psm, address_type=args.address_type)
    endpoint.validate()
    with _agent(args) as h:
        card = request_radio(endpoint, {"type": "profile"}, timeout=args.timeout)
        h.verify_id_card(card)
        old = h.peers.get(card["system_id"])
        if old is not None and old["card"]["public_key"] != card["public_key"]:
            raise FaspError("auth.peer_identity_changed", "Existing paired identity key cannot be replaced during registration.")
        if getattr(args, "as_name", None):
            _check_route_target(h, args.as_name, card["system_id"])
        response = request_radio(endpoint, {"type": "pair.hello", "id_card": h.id_card()}, timeout=args.timeout)
        if response.get("type") != "hello.ready" or response.get("system_id") != card["system_id"]:
            raise FaspError("auth.invalid_hello", "Bluetooth peer hello did not match the discovered identity.")
        verify(response, card["public_key"])
        response_card = response.get("id_card", {})
        h.verify_id_card(response_card)
        if response_card["system_id"] != card["system_id"] or response_card["public_key"] != card["public_key"]:
            raise FaspError("auth.invalid_hello", "Bluetooth peer changed identity between discovery and hello.")
        pending = h.hello(response_card)
        if response.get("pair_code") != pending.get("pair_code"):
            raise FaspError("auth.invalid_hello", "Pairing fingerprint differs between peers.")
        radios = h.state.get("agent-radios.json", {})
        radios[card["system_id"]] = endpoint.as_dict()
        h.state.put("agent-radios.json", radios)
        route = _bind_route(h, args.as_name, card["system_id"], allow_pending=True) if getattr(args, "as_name", None) else None
        _emit({"ok": True, "peer_id": card["system_id"], "name": card.get("display_name"), "state": h.peers.get(card["system_id"])["state"], "pair_code": pending["pair_code"], "route": route, "approval_required": True, "instructions": "Verify the fingerprint out of band, then approve on BOTH nodes."})
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        result = h.confirm_peer(_resolve_peer(h, args.peer), args.code, args.scope if args.scope else None)
        _emit(result)
    return 0


def cmd_peers(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        urls = h.state.get("agent-peers.json", {})
        radios = h.state.get("agent-radios.json", {})
        peers = [{"peer_id": pid, "name": entry["card"].get("display_name"), "state": entry["state"], "expires_at": entry["expires_at"], "scopes": entry["allowed_capability_prefixes"], "url": urls.get(pid), "radio": radios.get(pid)} for pid, entry in sorted(h.peers.all().items())]
        _emit({"peers": peers})
    return 0


def cmd_route(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        if args.route_action == "list":
            _emit({"routes": [{"name": name, "peer_id": peer} for name, peer in sorted(_routes(h).items())]})
        elif args.route_action == "add":
            name = _bind_route(h, args.name, _resolve_peer(h, args.peer) if args.peer.startswith("agent.") else args.peer)
            _emit({"ok": True, "name": name, "peer_id": _routes(h)[name]})
        else:
            name = _route_name(args.name)
            routes = _routes(h)
            if name not in routes:
                raise FaspError("config.route_missing", "Unknown local name.")
            peer = routes.pop(name)
            h.state.put("agent-routes.json", routes)
            _emit({"ok": True, "name": name, "peer_id": peer, "removed": True})
    return 0


def _load_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.payload_file:
        path = args.payload_file
        if path == "-":
            raw = sys.stdin.buffer.read(MAX_INLINE_BYTES + 1)
        else:
            with Path(path).open("rb") as source:
                raw = source.read(MAX_INLINE_BYTES + 1)
        if len(raw) > MAX_INLINE_BYTES:
            raise FaspError("resource.too_large", "Payload exceeds 64 KiB.")
        return decode_object(raw)
    return {}


def _queue_and_send(args: argparse.Namespace, kind: str, payload: dict[str, Any]) -> int:
    with _agent(args) as h:
        peer_id = _resolve_peer(h, args.peer)
        h._peer(peer_id)
        envelope = h.make_envelope(kind, peer_id, payload)
        outbox = Outbox(h.db)
        queued = outbox.enqueue(peer_id, envelope)
        metadata = {"peer_id": peer_id, "idempotency_key": payload.get("idempotency_key")}
        if "task_path" in payload:
            metadata["task_path"] = payload["task_path"]
        if args.queue_only:
            _emit({**metadata, "state": "queued", "message_id": queued.message_id, "expires_at": envelope["expires_at"]})
            return 0
        report = _deliver(h, args)
        record = outbox.get(queued.message_id)
        _emit({**metadata, "message_id": queued.message_id, "state": record["state"], "response": record["response"], "delivery": report})
        return 0 if record["state"] == "sent" else 3 if record["state"] == "pending" else 4


def cmd_communicate(args: argparse.Namespace) -> int:
    payload = _load_payload(args)
    payload.update({"idempotency_key": args.idempotency_key or str(uuid.uuid4()), "capability": args.capability})
    if args.message is not None:
        payload["objective"] = args.message
    if args.grant:
        payload["grant"] = {"id": args.grant}
    return _queue_and_send(args, "intent.propose", payload)


def cmd_say(args: argparse.Namespace) -> int:
    args.message = args.text
    args.payload_file = None
    args.capability = "coordinate.chat.v1"
    args.idempotency_key = None
    args.grant = None
    return cmd_communicate(args)


def cmd_speak(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        peer_id, task_name = _resolve_task_path(h, args.path)
    payload = _load_payload(args)
    if args.message is None and "objective" not in payload:
        raise FaspError("schema.invalid", "speak requires --message or an objective in --payload-file.")
    payload.update({"idempotency_key": args.idempotency_key or str(uuid.uuid4()), "capability": args.capability, "task_path": args.path, "task_name": task_name})
    if args.message is not None:
        payload["objective"] = args.message
    if args.grant:
        payload["grant"] = {"id": args.grant}
    args.peer = peer_id
    return _queue_and_send(args, "intent.propose", payload)


def cmd_send(args: argparse.Namespace) -> int:
    from .core import FaspHarness

    if not args.payload_file:
        raise FaspError("schema.invalid", "Raw signed messages require --payload-file JSON or --payload-file -.")
    if args.kind not in FaspHarness.DISPATCH:
        raise FaspError("protocol.unsupported_kind", "Unsupported FASP message kind.")
    return _queue_and_send(args, args.kind, _load_payload(args))


def cmd_drain(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        while True:
            last = _deliver(h, args)
            if not args.watch or last["delivered"] or last["retry"] or last["dead"]:
                _emit(last)
            if not args.watch:
                return 3 if last["retry"] else 4 if last["dead"] else 0
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                return 0


def cmd_outbox(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        outbox = Outbox(h.db)
        if args.message_id:
            record = outbox.get(args.message_id)
            if record is None:
                raise FaspError("schema.invalid", "Unknown outgoing message ID.")
            _emit(record)
        else:
            _emit({"depth": outbox.depth(), "dead_letters": outbox.dead_letters(limit=args.limit)})
    return 0


def cmd_task_status(args: argparse.Namespace) -> int:
    payload = {"idempotency_key": args.idempotency_key}
    return _queue_and_send(args, "task.status", payload)


def cmd_task_cancel(args: argparse.Namespace) -> int:
    return _queue_and_send(args, "task.cancel", {"idempotency_key": args.idempotency_key})


def cmd_task_reconcile(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        _emit(h.reconcile_task(args.idempotency_key))
    return 0


def cmd_relay_config(args: argparse.Namespace) -> int:
    from .transport.relay_client import RelayClient

    with _agent(args) as h:
        _emit(RelayClient.configure(h.state.directory, args.url, Path(args.token_file)))
    return 0


def cmd_relay_worker(args: argparse.Namespace) -> int:
    from .transport.relay_client import RelayClient

    with _agent(args) as h:
        client = RelayClient(h, ca_cert=args.ca_cert, timeout=args.timeout)
        next_reconcile = 0.0
        while True:
            if time.monotonic() >= next_reconcile:
                h.tasks.expire_stale_leases(stamp())
                h.recover_interrupted_intents()
                if callable(getattr(h.adapter, "reconcile", None)):
                    h.reconcile_unknown_tasks()
                next_reconcile = time.monotonic() + 10.0
            try:
                result = client.process_once()
            except FaspError as exc:
                if not args.watch or exc.code not in {"transport.unreachable", "transport.response_unavailable", "resource.exhausted"}:
                    raise
                _emit({"ok": False, "error": {"code": exc.code, "detail": exc.detail}})
            else:
                if not args.watch or result["received"]:
                    _emit(result)
            if not args.watch:
                return 0
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                return 0


def cmd_relay_authorize(args: argparse.Namespace) -> int:
    from .transport.relay_hub import RelayHub

    output = Path(args.output).expanduser()
    if output.exists():
        raise FaspError("config.already_exists", "Token output file already exists.")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    token = secrets.token_urlsafe(32)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        hub = RelayHub(_state_dir(args))
        try:
            hub.authorize(args.name, role=args.role, token=token)
        finally:
            hub.close()
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    _emit({"ok": True, "name": args.name, "role": args.role, "token_file": str(output)})
    return 0


def cmd_relay_route(args: argparse.Namespace) -> int:
    from .transport.relay_hub import RelayHub

    hub = RelayHub(_state_dir(args))
    try:
        hub.set_route(args.destination, args.url, args.account, Path(args.token_file), args.ca_cert)
    finally:
        hub.close()
    _emit({"ok": True, "destination": args.destination, "next_hop": args.url})
    return 0


def cmd_relay_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .transport.asgi_server import _tls13_only_context_factory
    from .transport.middleware import IPRateLimitMiddleware
    from .transport.relay_hub import RelayHub, create_relay_app

    if bool(args.tls_cert) != bool(args.tls_key):
        raise FaspError("config.invalid", "Relay TLS certificate and key must be supplied together.")
    if not args.tls_cert and args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise FaspError("transport.tls_required", "Public relay listeners require TLS.")
    hub = RelayHub(_state_dir(args))
    try:
        app = IPRateLimitMiddleware(create_relay_app(hub), rate_per_second=20.0, burst=40)
        config = uvicorn.Config(app, host=args.host, port=args.port, ssl_certfile=args.tls_cert, ssl_keyfile=args.tls_key, ssl_context_factory=_tls13_only_context_factory if args.tls_cert else None, limit_concurrency=256)
        uvicorn.Server(config).run()
    finally:
        hub.close()
    return 0


def cmd_tasks(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        rows = h.db.read("SELECT message_id, destination, state, envelope_json, response_json, created_at FROM outbox WHERE kind = 'intent.propose' ORDER BY row_id DESC LIMIT ?", (args.limit,))
        tasks = []
        for row in rows:
            payload = json.loads(row["envelope_json"])["payload"]
            tasks.append({"message_id": row["message_id"], "peer_id": row["destination"], "state": row["state"], "idempotency_key": payload.get("idempotency_key"), "task_path": payload.get("task_path"), "created_at": row["created_at"], "response": json.loads(row["response_json"]) if row["response_json"] else None})
        _emit({"tasks": tasks})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fasp", description="Connect systems with verified pairing and reliable signed messages. Terminal output is readable; pipes receive JSON.")
    subs = parser.add_subparsers(dest="command", required=True)

    def add(name: str, description: str, fn: Any) -> argparse.ArgumentParser:
        cmd = subs.add_parser(name, help=description)
        cmd.add_argument("--state-dir", default=os.environ.get("FASP_STATE_DIR", "~/.fasp-agent"), help="Private local state directory (or FASP_STATE_DIR).")
        cmd.set_defaults(handler=fn)
        return cmd

    init = add("init", "Create a local agent identity and durable state.", cmd_init)
    init.add_argument("--name", required=True)
    init.add_argument("--base-url", default="http://127.0.0.1:8766")
    init.add_argument("--insecure-http", action="store_true")

    add("id", "Print this agent's signed identity card.", cmd_id)
    import_card = add("import-card", "Import a signed peer ID card for offline or cross-NAT pairing.", cmd_import_card)
    import_card.add_argument("file")
    import_card.add_argument("--as", dest="as_name", help="Save a local agent name for this peer.")

    def network_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("--ca-cert", help="Custom TLS CA certificate bundle.")
        cmd.add_argument("--client-cert", help="Client certificate for mTLS.")
        cmd.add_argument("--client-key", help="Private key for the mTLS client certificate.")
        cmd.add_argument("--timeout", type=float, default=5.0)
        cmd.add_argument("--insecure-http", action="store_true", help="Allow unencrypted non-loopback HTTP for isolated development only.")

    scan = add("scan", "Find signed FASP devices on an explicitly authorized private CIDR.", cmd_scan)
    scan.add_argument("--cidr", required=True, help="Explicit private/local CIDR (e.g. 192.168.1.0/24).")
    scan.add_argument("--port", type=int, default=8766)
    scan.add_argument("--scheme", choices=("https", "http"), default="https")
    scan.add_argument("--workers", type=int, default=16)
    scan.add_argument("--allow-large", action="store_true", help="Explicitly permit 1025..65536 addresses.")
    network_flags(scan)
    scan.set_defaults(timeout=0.35)

    inspect = add("inspect", "Verify and inspect a device's signed live identity card.", cmd_inspect)
    inspect.add_argument("reference", help="HTTPS URL or exact discovered/registered FASP system ID.")
    network_flags(inspect)

    connect = add("connect", "Exchange signed identity cards and create PENDING pairing; never auto-approve.", cmd_connect)
    connect.add_argument("reference", help="HTTPS URL or exact discovered/registered FASP system ID.")
    connect.add_argument("--as", dest="as_name", help="Save a local name such as agent.researcher.")
    network_flags(connect)

    reg = add("register", "Compatibility alias of connect for an explicit HTTPS URL.", cmd_register)
    reg.add_argument("url", help="Peer node base HTTPS URL.")
    reg.add_argument("--as", dest="as_name", help="Save a local agent name for this peer.")
    network_flags(reg)

    radio = add("radio-register", "Exchange signed ID cards and request pending pairing over Bluetooth.", cmd_radio_register)
    radio.add_argument("address", help="Remote Bluetooth MAC address.")
    radio.add_argument("--mode", choices=("classic", "ble"), required=True)
    radio.add_argument("--channel", type=int, default=8, help="RFCOMM channel for Bluetooth Classic (default 8).")
    radio.add_argument("--psm", type=lambda value: int(value, 0), default=0x0080, help="BLE LE_PSM (default 0x0080).")
    radio.add_argument("--address-type", choices=("public", "random"), default="public")
    radio.add_argument("--timeout", type=float, default=10.0)
    radio.add_argument("--as", dest="as_name", help="Save a local agent name for this peer.")

    approve = add("approve", "Approve a pending peer locally after out-of-band code verification.", cmd_approve)
    approve.add_argument("peer", help="Full FASP system ID or local agent name.")
    approve.add_argument("--code", required=True, help="Pairing fingerprint verified with peer operator.")
    approve.add_argument("--scope", action="append", help="Explicit granted capability prefix; repeat.")

    disconnect = add("disconnect", "Revoke a known peer locally; cannot undo remote state.", cmd_disconnect)
    disconnect.add_argument("peer", help="Exact peer FASP system ID or local agent name.")
    disconnect.add_argument("--reason", default="operator disconnected peer")

    add("peers", "List pinned peers, pairing state and URLs.", cmd_peers)
    add("devices", "Alias of peers: list paired, pending and revoked device identities.", cmd_peers)

    route = add("route", "Manage local hierarchical names for paired peers.", cmd_route)
    route_subs = route.add_subparsers(dest="route_action", required=True)
    route_add = route_subs.add_parser("add", help="Bind agent.ROLE to a paired peer ID.")
    route_add.add_argument("name")
    route_add.add_argument("peer")
    route_remove = route_subs.add_parser("remove", help="Remove a local name.")
    route_remove.add_argument("name")
    route_subs.add_parser("list", help="List local names.")
    for action in (route_add, route_remove, route_subs.choices["list"]):
        action.add_argument("--state-dir", default=argparse.SUPPRESS)

    capabilities = add("capabilities", "List local or verified remote advertised capabilities.", cmd_capabilities)
    capabilities.add_argument("reference", nargs="?", help="Optional HTTPS URL or registered/discovered device ID.")
    network_flags(capabilities)

    add("status", "Show local identity, capability summary, peer states, and outbox.", cmd_status)

    def deliver_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("--limit", type=int, default=32, help="Max due messages per drain cycle.")
        cmd.add_argument("--transport", choices=("auto", "http", "radio", "relay"), default="auto", help="Bearer for signed delivery; auto tries direct HTTPS then a configured relay or Bluetooth.")
        network_flags(cmd)

    ping = add("ping", "Send an authenticated signed heartbeat to a paired device.", cmd_ping)
    ping.add_argument("peer", help="Exact paired FASP system ID or local agent name.")
    deliver_flags(ping)

    def message_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("peer", help="Destination's paired FASP system ID or local agent name.")
        cmd.add_argument("--payload-file", help="Read JSON payload from a file or '-' for stdin.")
        cmd.add_argument("--queue-only", action="store_true", help="Persist signed envelope without contacting the peer.")
        deliver_flags(cmd)

    chat = add("communicate", "Send a durable, signed capability intent.", cmd_communicate)
    message_flags(chat)
    chat.add_argument("--capability", default="coordinate.chat.v1", help="Declared capability on receiving agent.")
    chat.add_argument("--message", help="Objective/message for the receiving adapter.")
    chat.add_argument("--idempotency-key", help="Stable task identity for application-side deduplication.")
    chat.add_argument("--grant", help="Approved grant ID if the capability requires one.")

    say = add("say", "Send text to a paired system or local agent name.", cmd_say)
    say.add_argument("peer")
    say.add_argument("text")
    say.add_argument("--queue-only", action="store_true")
    deliver_flags(say)

    speak = add("speak", "Send a named text task such as agent.researcher.summarize.", cmd_speak)
    speak.add_argument("path")
    speak.add_argument("--payload-file")
    speak.add_argument("--message")
    speak.add_argument("--capability", default="coordinate.chat.v1")
    speak.add_argument("--idempotency-key")
    speak.add_argument("--grant")
    speak.add_argument("--queue-only", action="store_true")
    deliver_flags(speak)

    send = add("send", "Send a raw supported FASP kind with a JSON payload.", cmd_send)
    message_flags(send)
    send.add_argument("--kind", required=True)

    drain = add("drain", "Deliver pending signed messages with bounded retry and recovery.", cmd_drain)
    drain.add_argument("--watch", action="store_true", help="Keep draining until interrupted.")
    drain.add_argument("--interval", type=float, default=2.0, help="Seconds between watch cycles.")
    deliver_flags(drain)

    out = add("outbox", "Inspect durable outgoing message status and saved responses.", cmd_outbox)
    out.add_argument("message_id", nargs="?")
    out.add_argument("--limit", type=int, default=25)

    tasks = add("tasks", "List recent outgoing tasks and delivery states.", cmd_tasks)
    tasks.add_argument("--limit", type=int, default=25)

    status = add("task-status", "Query a peer's durable task state by key.", cmd_task_status)
    status.add_argument("peer")
    status.add_argument("idempotency_key")
    status.add_argument("--queue-only", action="store_true")
    deliver_flags(status)
    cancel = add("task-cancel", "Request cancellation by stable task key.", cmd_task_cancel)
    cancel.add_argument("peer")
    cancel.add_argument("idempotency_key")
    cancel.add_argument("--queue-only", action="store_true")
    deliver_flags(cancel)
    reconcile = add("task-reconcile", "Locally verify an interrupted task through the adapter's read-only reconcile hook.", cmd_task_reconcile)
    reconcile.add_argument("idempotency_key")
    reconcile.add_argument("--adapter", help="Adapter module:object or module:factory with reconcile(key, intent).")

    relay_config = add("relay-config", "Configure this node's outbound HTTPS relay using a private token file.", cmd_relay_config)
    relay_config.add_argument("url")
    relay_config.add_argument("--token-file", required=True)

    relay_worker = add("relay-worker", "Poll the relay for inbound encrypted messages and return signed outcomes.", cmd_relay_worker)
    relay_worker.add_argument("--watch", action="store_true")
    relay_worker.add_argument("--interval", type=float, default=0.5)
    relay_worker.add_argument("--timeout", type=float, default=5.0)
    relay_worker.add_argument("--ca-cert")
    relay_worker.add_argument("--adapter", help="Local adapter module:object or module:factory; use the same adapter as the node server.")

    relay_authorize = add("relay-authorize", "Issue a private token for one node or another relay.", cmd_relay_authorize)
    relay_authorize.add_argument("name")
    relay_authorize.add_argument("--role", choices=("client", "relay"), default="client")
    relay_authorize.add_argument("--output", required=True, help="New 0600 token file; transfer securely to the client.")

    relay_route = add("relay-route", "Forward one destination's opaque frames to the next HTTPS relay.", cmd_relay_route)
    relay_route.add_argument("destination")
    relay_route.add_argument("url")
    relay_route.add_argument("--account", required=True, help="Relay account issued by the next hop.")
    relay_route.add_argument("--token-file", required=True)
    relay_route.add_argument("--ca-cert", help="CA bundle for the next relay's HTTPS certificate.")

    relay_serve = add("relay-serve", "Run a bounded mailbox relay; public listeners require TLS.", cmd_relay_serve)
    relay_serve.add_argument("--host", default="127.0.0.1")
    relay_serve.add_argument("--port", type=int, default=8877)
    relay_serve.add_argument("--tls-cert")
    relay_serve.add_argument("--tls-key")
    return parser


def _normalize_pair_code_arg(argv: list[str]) -> list[str]:
    """Keep a URL-safe fingerprint starting with '-' usable after --code.

    argparse otherwise reads it as a new option. Pairing codes are exactly
    twelve URL-safe characters, so only that shape is rewritten.
    """
    if not argv or argv[0] != "approve":
        return argv
    for index in range(1, len(argv) - 1):
        if argv[index] == "--code" and re.fullmatch(r"-[A-Za-z0-9_-]{11}", argv[index + 1]):
            return [*argv[:index], f"--code={argv[index + 1]}", *argv[index + 2 :]]
    return argv


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--human" in raw and "--json" in raw:
        print(json.dumps({"ok": False, "error": {"code": "schema.invalid", "detail": "Choose either --human or --json."}}), file=sys.stderr)
        return 2
    human = "--human" in raw or ("--json" not in raw and sys.stdout.isatty())
    raw = [item for item in raw if item not in {"--human", "--json"}]
    args = build_parser().parse_args(_normalize_pair_code_arg(raw))
    token = _HUMAN_OUTPUT.set(human)
    try:
        timeout = getattr(args, "timeout", 5)
        limit = getattr(args, "limit", 32)
        interval = getattr(args, "interval", 2)
        if not math.isfinite(timeout) or timeout <= 0 or not 1 <= limit <= 256 or not math.isfinite(interval) or interval <= 0:
            raise FaspError("schema.invalid", "Timeout and drain interval must be finite and positive; queue batch limit must be 1..256.")
        if getattr(args, "client_key", None) and not args.client_cert:
            raise FaspError("schema.invalid", "--client-key requires --client-cert.")
        return int(args.handler(args))
    except (FaspError, RemoteRejection, TransportFailure, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (FaspError, RemoteRejection)) else "cli.error"
        detail = exc.detail if isinstance(exc, FaspError) else str(exc)
        problem = {"ok": False, "error": {"code": code, "detail": detail}}
        print(_render_human(problem) if human else json.dumps(problem, sort_keys=True), file=sys.stderr)
        return 2
    finally:
        _HUMAN_OUTPUT.reset(token)


def main_entry() -> int:
    # Keep the existing node server CLI available under the installed
    # "fasp" executable without changing its established flag parser.
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        from .transport.asgi_server import main as serve

        sys.argv.pop(1)
        serve()
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "discover":
        from .discovery import main as discover

        sys.argv.pop(1)
        discover()
        return 0
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
        build_parser().print_help()
        print("\nOutput: readable on a terminal, JSON when piped. Use --human or --json anywhere to override.")
        print("\nAlso available: serve, discover, mcp (optional extra).")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "mcp":
        from .mcp_server import main as mcp_main

        return mcp_main(sys.argv[2:])
    return main()


if __name__ == "__main__":
    sys.exit(main())
