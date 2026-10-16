"""Starlette ASGI application: the FASP HTTP baseline profile (ss13), plus
an optional live-push websocket layered on top of it.

Route design: a single generic signed-envelope ingress
(`POST /fasp/v1/envelopes`) dispatching on the envelope's `kind`, rather
than one bespoke route per verb. This is more spec-faithful (ss13 literally
specifies one ingress route) and more extensible -- a new message family
needs a new entry in `FaspHarness.DISPATCH` (core.py), not a new route plus
new server wiring. Kind support, auth, replay dedup, and metrics all live
in `FaspHarness.accept()` now; this module owns none of that -- it is a
thin translation to/from the synchronous `FaspHarness` API via
`run_in_threadpool` (the harness itself does not become async here;
`Database`'s own lock already serializes concurrent writes, this only
stops one slow adapter call from blocking every other connection's I/O).

`POST /fasp/v1/receipts` is kept as its own route only because ss13 names
it explicitly; it is a thin alias into the same `receipt.processed`
handling `/fasp/v1/envelopes` would give it anyway.

`/fasp/v1/channel` (a websocket) carries the identical envelope protocol
over one persistent connection instead of one HTTP request per envelope --
see `channels.py` and `FaspHarness.accept()`/`_apply_task_outcome` for how
a result that finishes after its synchronous caller gave up gets pushed
here instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections.abc import Awaitable, Callable
from datetime import timedelta
from functools import partial
from http import HTTPStatus
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from ..core import PROTOCOL, FaspError, FaspHarness
from ..edge.health import HealthRegistry
from ..observability.logging import configure, log
from ..protocol.contracts import operator_payload
from .canonical import MAX_ENVELOPE_BYTES, accept_envelope, decode_object
from .runtime import ChannelSession, IngressDispatcher, TransportLimits

logger = configure()

MAX_BODY_BYTES = MAX_ENVELOPE_BYTES

def _error_status(error: FaspError) -> int:
    if error.code == "transport.read_timeout":
        return HTTPStatus.REQUEST_TIMEOUT
    if error.code.startswith("auth."):
        return HTTPStatus.UNAUTHORIZED
    if error.code in {"capability.unavailable", "protocol.unsupported_kind"}:
        return HTTPStatus.NOT_FOUND
    if error.code == "resource.exhausted":
        return HTTPStatus.TOO_MANY_REQUESTS
    if error.code == "resource.too_large":
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    if error.code in {"transport.response_unavailable", "transport.overloaded"}:
        return HTTPStatus.SERVICE_UNAVAILABLE
    return HTTPStatus.BAD_REQUEST


def _error_response(error: FaspError) -> JSONResponse:
    return JSONResponse(
        {"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}},
        status_code=_error_status(error),
        headers={"Cache-Control": "no-store", **({"Retry-After": "1"} if error.code == "transport.overloaded" else {})},
    )


def _json_ok(payload: Any) -> JSONResponse:
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


def _catching(harness: FaspHarness) -> Callable[[Callable[[Request], Awaitable[JSONResponse]]], Callable[[Request], Awaitable[JSONResponse]]]:
    """Decorator factory: catch FaspError, count it, log it, and translate
    it to the matching HTTP response -- never a raw payload or traceback."""

    def decorator(handler: Callable[[Request], Awaitable[JSONResponse]]) -> Callable[[Request], Awaitable[JSONResponse]]:
        async def wrapped(request: Request) -> JSONResponse:
            try:
                return await handler(request)
            except FaspError as error:
                if error.code == "transport.overloaded":
                    return _error_response(error)
                harness.metrics.increment("fasp_auth_failures_total", code=error.code)
                log(logger, logging.WARNING, "request.rejected", code=error.code, path=request.url.path)
                return _error_response(error)

        return wrapped

    return decorator


async def _read_json_body(request: Request, *, timeout_s: float = 10.0) -> dict[str, Any]:
    body = bytearray()
    try:
        async with asyncio.timeout(timeout_s):
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_BODY_BYTES:
                    raise FaspError("resource.too_large", "Body exceeds 64 KiB.")
                body.extend(chunk)
    except TimeoutError as error:
        raise FaspError("transport.read_timeout", "Request body did not arrive before its deadline.") from error
    payload = decode_object(body)
    operator_payload(request.url.path, payload)
    return payload


def _live_gauges(harness: FaspHarness) -> dict[str, int]:
    """Point-in-time counts queried straight from the database, rather than
    tracked incrementally -- these change on their own (a lease expiring,
    a stream closing) independent of any request coming through here."""
    gauges: dict[str, int] = {}
    gauges["fasp_push_dropped_total"] = harness.channels.dropped
    gauges["fasp_push_pending_bytes"] = harness.channels.pending_bytes
    legacy_task_states = {
        "queued": "PROPOSED",
        "running": "RUNNING",
        "succeeded": "COMPLETED",
        "failed": "FAILED",
        "cancelled": "CANCELLED",
        "unknown": "UNKNOWN",
    }
    rows = harness.db.read(
        "SELECT kind, state, phase, COUNT(*) AS n FROM work_items GROUP BY kind, state, phase"
    )
    for row in rows:
        kind, state, phase, count = row["kind"], row["state"], row["phase"], row["n"]
        generic_key = f'fasp_work_items{{kind="{kind}",state="{state}"}}'
        gauges[generic_key] = gauges.get(generic_key, 0) + count
        if kind == "intent":
            legacy_state = legacy_task_states[state]
            if phase == "rejected":
                legacy_state = "REJECTED"
            elif phase == "cancel_requested":
                legacy_state = "CANCEL_PENDING"
            key = f'fasp_tasks{{state="{legacy_state}"}}'
            gauges[key] = gauges.get(key, 0) + count
        elif kind == "mission":
            if state == "succeeded":
                legacy_state = "COMPLETED"
            elif state == "cancelled":
                legacy_state = "CANCELLED"
            elif state == "failed":
                legacy_state = "REJECTED" if phase == "rejected" else "FAILED"
            else:
                legacy_state = str(phase or ("accepted" if state == "queued" else "running")).upper()
            key = f'fasp_missions{{state="{legacy_state}"}}'
            gauges[key] = gauges.get(key, 0) + count
    active_streams = harness.db.read_one("SELECT COUNT(*) AS n FROM streams WHERE state = 'open'")
    gauges["fasp_active_streams"] = active_streams["n"] if active_streams else 0
    active_reservations = harness.db.read_one("SELECT COUNT(*) AS n FROM reservations WHERE state = 'granted'")
    gauges["fasp_active_reservations"] = active_reservations["n"] if active_reservations else 0
    for row in harness.db.read("SELECT state, COUNT(*) AS n FROM outbox GROUP BY state"):
        gauges[f'fasp_outbox{{state="{row["state"]}"}}'] = row["n"]
    if harness.supervisor is not None:
        # Exported so an operator can alert on a latched halt or a stale
        # safety sample without polling an authenticated endpoint per node.
        status = harness.supervisor.current_status()
        gauges["fasp_safety_halt_latched"] = int(harness.supervisor.latched)
        gauges["fasp_safety_controller_reachable"] = int(status.reachable)
        gauges["fasp_safety_sample_stale"] = int(status.stale)
    return gauges


def _require_admin(request: Request, harness: FaspHarness) -> None:
    presented = request.headers.get("X-FASP-Admin-Token", "")
    # Timing-safe: the prior hand-rolled server used a plain `!=` here,
    # a timing side-channel on the one credential gating /peers and
    # /pair/confirm (contrast with the pair_code compare in peers_repo.py,
    # which already used secrets.compare_digest).
    if not secrets.compare_digest(presented, harness.admin_token):
        raise FaspError("auth.admin_required", "Local administrator token is required.")


def default_health(harness: FaspHarness) -> HealthRegistry:
    """The probes every node has, whether or not it coordinates a fleet.

    `database` is critical (a node that cannot reach its own durable state
    is wedged and should be restarted); the audit chain and the safety
    controller affect readiness only -- a node with a failing audit chain
    must stop receiving work and be looked at, not be silently restarted
    into the same state.
    """
    health = HealthRegistry(node_id=harness.display_name)
    health.register("database", lambda: (bool(harness.db.read_one("SELECT 1 AS ok")), "sqlite reachable"), critical=True)
    health.register("audit-chain", lambda: (harness.audit.verify()[0], "hash chain verifies"))
    if harness.supervisor is not None:
        health.register("safety-controller", lambda: (harness.supervisor.current_status().reachable, harness.supervisor.current_status().detail or "controller reachable"))
    health.mark_started()
    return health


def create_app(harness: FaspHarness, health: HealthRegistry | None = None, before_close: Callable[[], None] | None = None, *, transport_limits: TransportLimits | None = None) -> Starlette:
    catching = _catching(harness)
    health = health or default_health(harness)
    limits = transport_limits or TransportLimits()
    ingress = IngressDispatcher(limits, harness.metrics)
    active_channels = 0

    @catching
    async def get_profile(request: Request) -> JSONResponse:
        return _json_ok(await run_in_threadpool(harness.id_card))

    async def get_openapi(request: Request) -> JSONResponse:
        del request
        from .openapi import schema

        return _json_ok(schema())

    async def get_wire_schema(request: Request) -> JSONResponse:
        del request
        from ..protocol.schemas import wire_schema

        return _json_ok(wire_schema())

    @catching
    async def get_health(request: Request) -> JSONResponse:
        return _json_ok({"ok": True, "fasp": PROTOCOL, "system_id": harness.identity.system_id})

    @catching
    async def get_peers(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        return _json_ok(await run_in_threadpool(harness.peers.all))

    @catching
    async def get_metrics(request: Request) -> PlainTextResponse:
        _require_admin(request, harness)
        gauges = await run_in_threadpool(_live_gauges, harness)
        gauges.update(ingress.gauges())
        gauges["fasp_channel_sessions"] = active_channels
        return PlainTextResponse(harness.metrics.render(gauges), headers={"Cache-Control": "no-store"})

    @catching
    async def get_livez(request: Request) -> JSONResponse:
        """Is this process wedged? A failure here means restart me.

        Public and minimal: an orchestrator needs a status code, and the
        names of internal checks are not something to hand to anyone who
        can reach the port. `/health` (admin) carries the detail.
        """
        del request
        live, body = await run_in_threadpool(health.live)
        return JSONResponse({"ok": live, "state": body["state"]}, status_code=HTTPStatus.OK if live else HTTPStatus.SERVICE_UNAVAILABLE, headers={"Cache-Control": "no-store"})

    @catching
    async def get_readyz(request: Request) -> JSONResponse:
        """Should this node receive work? A standby answers no, and is fine."""
        del request
        ready, body = await run_in_threadpool(health.ready)
        return JSONResponse({"ok": ready, "state": body["state"]}, status_code=HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE, headers={"Cache-Control": "no-store"})

    @catching
    async def get_health_detail(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        return _json_ok(await run_in_threadpool(health.snapshot))

    @catching
    async def get_safety(request: Request) -> JSONResponse:
        """Layer 1 evidence for a local operator: read-only, like everything
        else that touches Layer 1 in this process."""
        _require_admin(request, harness)
        if harness.supervisor is None:
            raise FaspError("capability.unavailable", "This system observes no safety controller.")
        return _json_ok(await run_in_threadpool(harness.supervisor.evidence))

    @catching
    async def get_fleet(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        if harness.missions is None:
            raise FaspError("capability.unavailable", "This system does not coordinate a fleet.")
        return _json_ok(await run_in_threadpool(harness.missions.overview))

    @catching
    async def post_pair_hello(request: Request) -> JSONResponse:
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        result = await run_in_threadpool(harness.hello, payload.get("id_card", {}))
        return _json_ok(result)

    @catching
    async def post_pair_confirm(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        result = await run_in_threadpool(
            harness.confirm_peer, payload.get("peer_id", ""), payload.get("pair_code", ""), payload.get("allowed_capability_prefixes")
        )
        return _json_ok(result)

    @catching
    async def post_pair_revoke(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        result = await run_in_threadpool(
            harness.revoke_peer, payload.get("peer_id", ""), payload.get("reason", "revoked by local operator"), payload.get("revocation_ref")
        )
        return _json_ok(result)

    @catching
    async def post_grants_issue(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        duration = timedelta(seconds=payload.get("duration_seconds", 3600))
        result = await run_in_threadpool(
            harness.issue_grant, payload.get("subject_peer", ""), payload.get("capability_prefixes", []), duration, payload.get("purpose"), payload.get("constraints")
        )
        return _json_ok(result)

    @catching
    async def post_grants_revoke(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        result = await run_in_threadpool(harness.revoke_grant, payload.get("grant_id", ""))
        return _json_ok(result)

    @catching
    async def post_envelopes(request: Request) -> JSONResponse:
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        response = await ingress.run(payload, partial(accept_envelope, harness, payload))
        return _json_ok(response)

    @catching
    async def post_receipts(request: Request) -> JSONResponse:
        payload = await _read_json_body(request, timeout_s=limits.body_timeout_s)
        response = await ingress.run(payload, partial(accept_envelope, harness, payload, expected_kind="receipt.processed", wrap_receipt=False))
        return _json_ok(response)

    async def channel_endpoint(websocket: WebSocket) -> None:
        nonlocal active_channels
        # Include unauthenticated and closing sockets in the same bound.
        if active_channels >= limits.max_channels:
            harness.metrics.increment("fasp_channel_rejected_total", reason="capacity")
            await websocket.close(code=1013)
            return
        active_channels += 1
        session = ChannelSession(websocket, limits.send_timeout_s)
        registered_peer: str | None = None
        failures = 0
        loop = asyncio.get_running_loop()
        auth_deadline = loop.time() + limits.auth_timeout_s
        close_code = 1000
        try:
            await websocket.accept()
            while True:
                async with asyncio.timeout_at(auth_deadline if registered_peer is None else None):
                    frame = await websocket.receive()
                    if frame["type"] == "websocket.disconnect":
                        break
                    if frame.get("text") is None:
                        close_code = 1003
                        break
                    raw = frame["text"].encode("utf-8")
                    try:
                        payload = decode_object(raw)
                    except FaspError as error:
                        await session.send_json({"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}})
                        close_code = 1009 if error.code == "resource.too_large" else 1007
                        break
                    message_id = payload.get("message_id")
                    correlation = {"in_reply_to": message_id} if isinstance(message_id, str) and 1 <= len(message_id) <= 128 else {}
                    # Reject a different claimed identity before any effects or
                    # dispatch. An unverified frame can never rebind this socket.
                    if registered_peer is not None and payload.get("from") != registered_peer:
                        await session.send_json({"fasp": PROTOCOL, "type": "protocol.error", **correlation,
                                                 "error": {"code": "auth.channel_identity", "detail": "Open a separate channel for a different peer identity."}})
                        close_code = 1008
                        break
                    try:
                        response = await ingress.run(payload, partial(accept_envelope, harness, payload))
                    except FaspError as error:
                        harness.metrics.increment("fasp_channel_errors_total", code=error.code)
                        await session.send_json({"fasp": PROTOCOL, "type": "protocol.error", **correlation,
                                                 "error": {"code": error.code, "detail": error.detail}})
                        # Saturation is retryable, and must not disconnect a
                        # healthy authenticated client. Invalid traffic is bounded.
                        if error.code != "transport.overloaded":
                            failures += 1
                        if failures >= limits.max_invalid_frames:
                            close_code = 1008
                            break
                        continue
                    if registered_peer is None:
                        sender = payload["from"]
                        if not harness.channels.register(sender, session):
                            close_code = 1013
                            break
                        registered_peer = sender
                    failures = 0
                    await session.send_json({**response, **correlation})
        except TimeoutError:
            harness.metrics.increment("fasp_channel_rejected_total", reason="timeout")
            close_code = 1008 if registered_peer is None else 1013
        except (WebSocketDisconnect, ConnectionError, OSError):
            pass
        finally:
            if registered_peer is not None:
                harness.channels.unregister(registered_peer, session)
            try:
                with contextlib.suppress(WebSocketDisconnect, RuntimeError, TimeoutError, OSError):
                    await session.close(code=close_code)
            finally:
                active_channels -= 1

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        del app
        harness.channels.bind_loop(asyncio.get_running_loop())
        try:
            yield
        finally:
            try:
                if before_close is not None:
                    await run_in_threadpool(before_close)
            finally:
                # Graceful drain (ss15 #5/#6): let in-flight adapter calls
                # finish on their own rather than abandoning them mid-call the
                # moment the process is asked to stop.
                await run_in_threadpool(ingress.close)
                await run_in_threadpool(harness.close)

    return Starlette(
        lifespan=lifespan,
        routes=[
            Route("/openapi.json", get_openapi, methods=["GET"]),
            Route("/schemas/fasp-wire-v1.json", get_wire_schema, methods=["GET"]),
            Route("/profile", get_profile, methods=["GET"]),
            Route("/.well-known/fasp/id-card.json", get_profile, methods=["GET"]),
            Route("/health", get_health, methods=["GET"]),
            Route("/livez", get_livez, methods=["GET"]),
            Route("/readyz", get_readyz, methods=["GET"]),
            Route("/health/detail", get_health_detail, methods=["GET"]),
            Route("/safety", get_safety, methods=["GET"]),
            Route("/fleet", get_fleet, methods=["GET"]),
            Route("/peers", get_peers, methods=["GET"]),
            Route("/metrics", get_metrics, methods=["GET"]),
            Route("/pair/hello", post_pair_hello, methods=["POST"]),
            Route("/pair/confirm", post_pair_confirm, methods=["POST"]),
            Route("/pair/revoke", post_pair_revoke, methods=["POST"]),
            Route("/grants/issue", post_grants_issue, methods=["POST"]),
            Route("/grants/revoke", post_grants_revoke, methods=["POST"]),
            Route("/fasp/v1/envelopes", post_envelopes, methods=["POST"]),
            Route("/fasp/v1/receipts", post_receipts, methods=["POST"]),
            WebSocketRoute("/fasp/v1/channel", channel_endpoint),
        ],
    )
