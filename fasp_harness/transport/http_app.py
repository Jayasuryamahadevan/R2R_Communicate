"""Starlette ASGI application: the FASP HTTP baseline profile (ss13).

Route design: a single generic signed-envelope ingress
(`POST /fasp/v1/envelopes`) dispatching on the envelope's `kind`, rather
than one bespoke route per verb. This is more spec-faithful (ss13 literally
specifies one ingress route) and more extensible -- a new message family
needs a new dispatch-table entry, not a new route plus new server wiring.

`POST /fasp/v1/receipts` is kept as its own route only because ss13 names
it explicitly; it is a thin alias into the same `receipt.processed`
handling `/fasp/v1/envelopes` would give it anyway.

Every handler stays a thin translation to/from the synchronous
`FaspHarness` API (unchanged since Phase 2-5) via `run_in_threadpool` --
the harness itself does not become async here. `FaspHarness`'s own
internal locking (one `threading.Lock`-guarded SQLite connection) already
serializes concurrent writes correctly; this only stops one slow adapter
call from blocking every other connection's I/O.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
from collections.abc import Awaitable, Callable
from datetime import timedelta
from http import HTTPStatus
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from ..core import PROTOCOL, FaspError, FaspHarness
from ..observability.logging import configure, log

logger = configure()

MAX_BODY_BYTES = 64 * 1024

# Kinds whose HTTP response is wrapped in a `receipt.delivered` envelope --
# the two-phase "delivery receipt is not a completion receipt" shape ss7.1
# requires specifically for the task lifecycle. Every other kind's response
# is returned as-is: it's a plain request/response RPC, not a durable job.
# Kind support and dispatch itself is entirely `FaspHarness.accept()`'s
# job now (`core.py`'s `DISPATCH` table) -- this transport module no longer
# keeps its own parallel copy of that mapping.
RECEIPT_WRAPPED_KINDS = frozenset({"intent.propose", "task.cancel", "artifact.fetch"})


def _error_status(error: FaspError) -> int:
    if error.code.startswith("auth."):
        return HTTPStatus.UNAUTHORIZED
    if error.code in {"capability.unavailable", "protocol.unsupported_kind"}:
        return HTTPStatus.NOT_FOUND
    if error.code in {"resource.too_large", "resource.exhausted"}:
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    return HTTPStatus.BAD_REQUEST


def _error_response(error: FaspError) -> JSONResponse:
    return JSONResponse(
        {"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}},
        status_code=_error_status(error),
        headers={"Cache-Control": "no-store"},
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
                harness.metrics.increment("fasp_auth_failures_total", code=error.code)
                log(logger, logging.WARNING, "request.rejected", code=error.code, path=request.url.path)
                return _error_response(error)

        return wrapped

    return decorator


async def _read_json_body(request: Request) -> dict[str, Any]:
    body = await request.body()
    if not 1 <= len(body) <= MAX_BODY_BYTES:
        raise FaspError("schema.invalid", "Body must be a JSON object smaller than 64 KiB.")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise FaspError("schema.invalid", "Body is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise FaspError("schema.invalid", "Body must be a JSON object.")
    return payload


def _live_gauges(harness: FaspHarness) -> dict[str, int]:
    """Point-in-time counts queried straight from the database, rather than
    tracked incrementally -- these change on their own (a lease expiring,
    a stream closing) independent of any request coming through here."""
    gauges: dict[str, int] = {}
    for row in harness.db.read("SELECT state, COUNT(*) AS n FROM tasks GROUP BY state"):
        gauges[f'fasp_tasks{{state="{row["state"]}"}}'] = row["n"]
    active_streams = harness.db.read_one("SELECT COUNT(*) AS n FROM streams WHERE state = 'open'")
    gauges["fasp_active_streams"] = active_streams["n"] if active_streams else 0
    active_reservations = harness.db.read_one("SELECT COUNT(*) AS n FROM reservations WHERE state = 'granted'")
    gauges["fasp_active_reservations"] = active_reservations["n"] if active_reservations else 0
    return gauges


def _require_admin(request: Request, harness: FaspHarness) -> None:
    presented = request.headers.get("X-FASP-Admin-Token", "")
    # Timing-safe: the prior hand-rolled server used a plain `!=` here,
    # a timing side-channel on the one credential gating /peers and
    # /pair/confirm (contrast with the pair_code compare in peers_repo.py,
    # which already used secrets.compare_digest).
    if not secrets.compare_digest(presented, harness.admin_token):
        raise FaspError("auth.admin_required", "Local administrator token is required.")


def create_app(harness: FaspHarness) -> Starlette:
    catching = _catching(harness)

    @catching
    async def get_profile(request: Request) -> JSONResponse:
        return _json_ok(await run_in_threadpool(harness.id_card))

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
        return PlainTextResponse(harness.metrics.render(gauges), headers={"Cache-Control": "no-store"})

    @catching
    async def post_pair_hello(request: Request) -> JSONResponse:
        payload = await _read_json_body(request)
        result = await run_in_threadpool(harness.hello, payload.get("id_card", {}))
        return _json_ok(result)

    @catching
    async def post_pair_confirm(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request)
        result = await run_in_threadpool(
            harness.confirm_peer, payload.get("peer_id", ""), payload.get("pair_code", ""), payload.get("allowed_capability_prefixes")
        )
        return _json_ok(result)

    @catching
    async def post_pair_revoke(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request)
        result = await run_in_threadpool(
            harness.revoke_peer, payload.get("peer_id", ""), payload.get("reason", "revoked by local operator"), payload.get("revocation_ref")
        )
        return _json_ok(result)

    @catching
    async def post_grants_issue(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request)
        duration = timedelta(seconds=int(payload.get("duration_seconds", 3600)))
        result = await run_in_threadpool(
            harness.issue_grant, payload.get("subject_peer", ""), payload.get("capability_prefixes", []), duration, payload.get("purpose"), payload.get("constraints")
        )
        return _json_ok(result)

    @catching
    async def post_grants_revoke(request: Request) -> JSONResponse:
        _require_admin(request, harness)
        payload = await _read_json_body(request)
        result = await run_in_threadpool(harness.revoke_grant, payload.get("grant_id", ""))
        return _json_ok(result)

    @catching
    async def post_envelopes(request: Request) -> JSONResponse:
        payload = await _read_json_body(request)
        duplicate, response = await run_in_threadpool(harness.accept, payload)
        if payload.get("kind") in RECEIPT_WRAPPED_KINDS:
            return _json_ok({"fasp": PROTOCOL, "type": "receipt.delivered", "duplicate": duplicate, "message_id": payload.get("message_id"), "response": response})
        return _json_ok(response)

    @catching
    async def post_receipts(request: Request) -> JSONResponse:
        payload = await _read_json_body(request)
        _, response = await run_in_threadpool(harness.accept, payload, "receipt.processed")
        return _json_ok(response)

    async def channel_endpoint(websocket: WebSocket) -> None:
        """`/fasp/v1/channel`: the same signed-envelope protocol as
        `/fasp/v1/envelopes`, just carried over a persistent, full-duplex
        connection instead of one HTTP request per envelope (ss13's
        transport-agnostic framing: only the wire *transport* differs here,
        never the envelope format, auth, or dedup semantics).

        There is no separate handshake message: the first authenticated
        frame's `from` registers this connection for push delivery (see
        `channels.py` and `FaspHarness._apply_task_outcome`), and every
        later frame -- of any dispatchable kind -- is handled exactly as an
        HTTP POST would handle it.
        """
        await websocket.accept()
        registered_peer: str | None = None
        try:
            while True:
                try:
                    payload = await websocket.receive_json()
                except (ValueError, WebSocketDisconnect):
                    break
                if not isinstance(payload, dict):
                    await websocket.send_json({"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": "schema.invalid", "detail": "Frame must be a JSON object."}})
                    continue
                try:
                    duplicate, response = await run_in_threadpool(harness.accept, payload)
                except FaspError as error:
                    harness.metrics.increment("fasp_auth_failures_total", code=error.code)
                    await websocket.send_json({"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": error.code, "detail": error.detail}})
                    continue
                sender = payload.get("from")
                if isinstance(sender, str) and sender != registered_peer:
                    if registered_peer is not None:
                        harness.channels.unregister(registered_peer, websocket)
                    harness.channels.register(sender, websocket)
                    registered_peer = sender
                if payload.get("kind") in RECEIPT_WRAPPED_KINDS:
                    await websocket.send_json({"fasp": PROTOCOL, "type": "receipt.delivered", "duplicate": duplicate, "message_id": payload.get("message_id"), "response": response})
                else:
                    await websocket.send_json(response)
        finally:
            if registered_peer is not None:
                harness.channels.unregister(registered_peer, websocket)

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        del app
        harness.channels.bind_loop(asyncio.get_running_loop())
        try:
            yield
        finally:
            # Graceful drain (ss15 #5/#6): let in-flight adapter calls
            # finish on their own rather than abandoning them mid-call the
            # moment the process is asked to stop.
            await run_in_threadpool(harness.close)

    return Starlette(
        lifespan=lifespan,
        routes=[
            Route("/profile", get_profile, methods=["GET"]),
            Route("/.well-known/fasp/id-card.json", get_profile, methods=["GET"]),
            Route("/health", get_health, methods=["GET"]),
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
