"""Agent-oriented CLI: explicit pairing, signed RPCs, and durable delivery.

All wire operations use the existing FASP v1 protocol and trust model.
'register' is a two-sided pending pairing ceremony, NOT automatic trust.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import re
import ssl
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from .core import MAX_INLINE_BYTES, FaspHarness
from .crypto.envelope import verify
from .edge.outbox import Outbox
from .protocol.errors import FaspError
from .transport.canonical import decode_object

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
AGENT_COMMANDS = frozenset({"init", "id", "register", "radio-register", "approve", "peers", "communicate", "send", "drain", "outbox", "task-status"})


class RemoteRejection(Exception):
    def __init__(self, code: str, detail: str, status: int) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.status = status


class TransportFailure(Exception):
    pass


def _emit(data: Any) -> None:
    # Single JSON object per invocation; stable for agent/tool consumers.
    print(json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


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
    state = _state_dir(args)
    if not (state / "identity.json").is_file():
        raise FaspError("config.not_initialized", "First run: fasp init --name NAME --state-dir PATH")
    config_file = state / "agent.json"
    config = json.loads(config_file.read_text(encoding="utf-8")) if config_file.exists() else {}
    return FaspHarness(state, config.get("name", "fasp-agent"), config.get("base_url", "http://127.0.0.1:8766"))


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


def _peer_endpoint(harness: FaspHarness, peer_id: str, args: argparse.Namespace) -> str:
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
    if transport == "auto":
        transport = "http" if peer_id in harness.state.get("agent-peers.json", {}) else "radio"
    if transport == "http":
        return request_json(_peer_endpoint(harness, peer_id, args), envelope, args)

    from .transport.radio import request_radio

    endpoint = _radio_endpoint(harness, peer_id)
    card = request_radio(endpoint, {"type": "profile"}, timeout=args.timeout)
    harness.verify_id_card(card)
    pinned = harness._peer(peer_id)
    if card["system_id"] != peer_id or card["public_key"] != pinned["card"]["public_key"]:
        raise FaspError("auth.peer_identity_changed", "Live Bluetooth peer differs from the pinned pairing identity.")
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


def cmd_register(args: argparse.Namespace) -> int:
    base = _base_url(args.url, args.insecure_http)
    with _agent(args) as h:
        card = request_json(base + "/profile", None, args)
        h.verify_id_card(card)
        old = h.peers.get(card["system_id"])
        if old is not None and old["card"]["public_key"] != card["public_key"]:
            raise FaspError("auth.peer_identity_changed", "Existing paired identity key cannot be replaced during registration.")
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
        _emit({"ok": True, "peer_id": card["system_id"], "name": card.get("display_name"), "state": h.peers.get(card["system_id"])["state"], "pair_code": pending["pair_code"], "approval_required": True, "instructions": "Verify the fingerprint out of band, then approve on BOTH nodes."})
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
        _emit({"ok": True, "peer_id": card["system_id"], "name": card.get("display_name"), "state": h.peers.get(card["system_id"])["state"], "pair_code": pending["pair_code"], "approval_required": True, "instructions": "Verify the fingerprint out of band, then approve on BOTH nodes."})
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        result = h.confirm_peer(args.peer, args.code, args.scope if args.scope else None)
        _emit(result)
    return 0


def cmd_peers(args: argparse.Namespace) -> int:
    with _agent(args) as h:
        urls = h.state.get("agent-peers.json", {})
        radios = h.state.get("agent-radios.json", {})
        peers = [{"peer_id": pid, "name": entry["card"].get("display_name"), "state": entry["state"], "expires_at": entry["expires_at"], "scopes": entry["allowed_capability_prefixes"], "url": urls.get(pid), "radio": radios.get(pid)} for pid, entry in sorted(h.peers.all().items())]
        _emit({"peers": peers})
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
        h._peer(args.peer)
        envelope = h.make_envelope(kind, args.peer, payload)
        outbox = Outbox(h.db)
        queued = outbox.enqueue(args.peer, envelope)
        if args.queue_only:
            _emit({"state": "queued", "message_id": queued.message_id, "expires_at": envelope["expires_at"]})
            return 0
        report = _deliver(h, args)
        record = outbox.get(queued.message_id)
        _emit({"message_id": queued.message_id, "state": record["state"], "response": record["response"], "delivery": report})
        return 0 if record["state"] == "sent" else 3 if record["state"] == "pending" else 4


def cmd_communicate(args: argparse.Namespace) -> int:
    payload = _load_payload(args)
    payload.update({"idempotency_key": args.idempotency_key or str(uuid.uuid4()), "capability": args.capability})
    if args.message is not None:
        payload["objective"] = args.message
    if args.grant:
        payload["grant"] = {"id": args.grant}
    return _queue_and_send(args, "intent.propose", payload)


def cmd_send(args: argparse.Namespace) -> int:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fasp", description="FASP agent CLI: explicit trust and reliable signed task delivery.")
    subs = parser.add_subparsers(dest="command", required=True)

    def add(name: str, description: str, fn: Any) -> argparse.ArgumentParser:
        cmd = subs.add_parser(name, help=description)
        cmd.add_argument("--state-dir", default="~/.fasp-agent", help="Private local state directory.")
        cmd.set_defaults(handler=fn)
        return cmd

    init = add("init", "Create a local agent identity and durable state.", cmd_init)
    init.add_argument("--name", required=True)
    init.add_argument("--base-url", default="http://127.0.0.1:8766")
    init.add_argument("--insecure-http", action="store_true")

    add("id", "Print this agent's signed identity card.", cmd_id)

    def network_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("--ca-cert", help="Custom TLS CA certificate bundle.")
        cmd.add_argument("--client-cert", help="Client certificate for mTLS.")
        cmd.add_argument("--client-key", help="Private key for the mTLS client certificate.")
        cmd.add_argument("--timeout", type=float, default=5.0)
        cmd.add_argument("--insecure-http", action="store_true", help="Allow unencrypted non-loopback HTTP for isolated development only.")

    reg = add("register", "Exchange verified ID cards and request pending pairing.", cmd_register)
    reg.add_argument("url", help="Peer node base HTTPS URL.")
    network_flags(reg)

    radio = add("radio-register", "Exchange signed ID cards and request pending pairing over Bluetooth.", cmd_radio_register)
    radio.add_argument("address", help="Remote Bluetooth MAC address.")
    radio.add_argument("--mode", choices=("classic", "ble"), required=True)
    radio.add_argument("--channel", type=int, default=8, help="RFCOMM channel for Bluetooth Classic (default 8).")
    radio.add_argument("--psm", type=lambda value: int(value, 0), default=0x0080, help="BLE LE_PSM (default 0x0080).")
    radio.add_argument("--address-type", choices=("public", "random"), default="public")
    radio.add_argument("--timeout", type=float, default=10.0)

    approve = add("approve", "Approve a pending peer locally after out-of-band code verification.", cmd_approve)
    approve.add_argument("peer", help="Full FASP system ID.")
    approve.add_argument("--code", required=True, help="Pairing fingerprint verified with peer operator.")
    approve.add_argument("--scope", action="append", help="Explicit granted capability prefix; repeat.")

    add("peers", "List pinned peers, pairing state and URLs.", cmd_peers)

    def deliver_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("--limit", type=int, default=32, help="Max due messages per drain cycle.")
        cmd.add_argument("--transport", choices=("auto", "http", "radio"), default="auto", help="Bearer for signed delivery; auto prefers a registered HTTPS endpoint.")
        network_flags(cmd)

    def message_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("peer", help="Destination's exact paired FASP system ID.")
        cmd.add_argument("--payload-file", help="Read JSON payload from a file or '-' for stdin.")
        cmd.add_argument("--queue-only", action="store_true", help="Persist signed envelope without contacting the peer.")
        deliver_flags(cmd)

    chat = add("communicate", "Send a durable, signed capability intent.", cmd_communicate)
    message_flags(chat)
    chat.add_argument("--capability", default="coordinate.chat.v1", help="Declared capability on receiving agent.")
    chat.add_argument("--message", help="Objective/message for the receiving adapter.")
    chat.add_argument("--idempotency-key", help="Stable task identity for application-side deduplication.")
    chat.add_argument("--grant", help="Approved grant ID if the capability requires one.")

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

    status = add("task-status", "Query a peer's durable task state by key.", cmd_task_status)
    status.add_argument("peer")
    status.add_argument("idempotency_key")
    status.add_argument("--queue-only", action="store_true")
    deliver_flags(status)
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
    args = build_parser().parse_args(_normalize_pair_code_arg(list(sys.argv[1:] if argv is None else argv)))
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
        print(json.dumps({"ok": False, "error": {"code": code, "detail": detail}}, sort_keys=True), file=sys.stderr)
        return 2


def main_entry() -> int:
    # Keep the existing node server CLI available under the installed
    # "fasp" executable without changing its established flag parser.
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        from .transport.asgi_server import main as serve

        sys.argv.pop(1)
        serve()
        return 0
    return main()


if __name__ == "__main__":
    sys.exit(main())
