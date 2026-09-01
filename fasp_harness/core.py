"""Core primitives for the Federated Autonomous Systems Protocol harness.

The harness deliberately provides coordination, not remote code execution.
Model-specific behaviour is supplied by an Adapter and remains subject to the
local capability and risk policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn, Protocol

from .artifacts.store import ArtifactStore
from .audit.chain import AuditChain
from .channels import ConnectionRegistry
from .crypto.envelope import FaspError, b64, sign, unb64, unsigned, verify
from .crypto.identity import Identity
from .fleet.model import Mission
from .fleet.service import MissionService
from .layers import CapabilityDeclaration, LayerGuard, describe_layers
from .observability.metrics import MetricsRegistry
from .platforms import runtime_profile
from .policy import capability as capability_policy
from .policy.grants import validate_grant_if_required
from .policy.ratelimit import TokenBucketLimiter
from .robotics import LocalSafetyGate, ReservationBook
from .safety.interlock import SafetySupervisor
from .storage.db import Database
from .storage.grants_repo import GrantsRepo
from .storage.inbox_repo import InboxRepo
from .storage.peers_repo import PeersRepo
from .storage.reservations_repo import ReservationsRepo
from .storage.revocations_repo import RevocationsRepo
from .storage.streams_repo import StreamsRepo
from .storage.tasks_repo import TERMINAL_STATES, TasksRepo
from .streaming import StreamRegistry
from .timestamps import now, parse_stamp, stamp

PEER_PAIRING_VALIDITY = timedelta(days=90)
DEFAULT_TASK_LEASE = timedelta(seconds=30)
ARTIFACT_INLINE_THRESHOLD_BYTES = 8 * 1024
ARTIFACT_RETENTION = timedelta(days=7)
DEFAULT_ADAPTER_CONCURRENCY = 8
DEFAULT_MAX_INFLIGHT_TASKS = 256

__all__ = [
    "FaspError",
    "Identity",
    "JsonState",
    "DefaultSafeAdapter",
    "FaspHarness",
    "SafeAdapter",
    "b64",
    "unb64",
    "sign",
    "verify",
    "unsigned",
    "now",
    "stamp",
    "parse_stamp",
    "PROTOCOL",
    "MAX_INLINE_BYTES",
    "MAX_CLOCK_SKEW_SECONDS",
]

PROTOCOL = "fasp/1.0"
MAX_INLINE_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 60


def _task_response(task: dict[str, Any]) -> dict[str, Any]:
    """Render a `tasks` row as the response shape its state implies.

    Used both for a duplicate intent.propose (return the prior outcome
    rather than re-running anything) and for task.cancel racing against
    completion (report whatever the row's state actually resolved to).
    """
    state = task["state"]
    if state == "COMPLETED":
        return task["result"]
    if state == "FAILED":
        error = task["error"] or {}
        return {"type": "task.fail", "intent_id": task["intent_id"], "idempotency_key": task["idempotency_key"], "status": "failed", "error": error, "completed_at": task["updated_at"]}
    if state == "CANCELLED":
        return {"type": "task.cancelled", "idempotency_key": task["idempotency_key"]}
    if state == "REJECTED":
        error = task["error"] or {}
        return {"type": "task.fail", "intent_id": task["intent_id"], "idempotency_key": task["idempotency_key"], "status": "rejected", "error": error, "completed_at": task["updated_at"]}
    # PROPOSED / RUNNING / CANCEL_PENDING: not yet resolved to a terminal
    # outcome. This reference harness's synchronous adapter model makes
    # observing one of these from a second caller rare, but not impossible
    # under real thread concurrency (see tests/test_cancellation.py).
    return {"type": "task.progress", "idempotency_key": task["idempotency_key"], "status": state.lower()}


def _plain_json(value: Any) -> bytes:
    """Deterministic-enough local bookkeeping serialization.

    Deliberately NOT the RFC 8785 canonicalizer in `.crypto.canonical`: that
    canonicalizer enforces the IEEE 754 safe-integer domain (+-2**53-1),
    which is correct for anything that gets signed but wrong for purely
    local state such as `time.monotonic_ns()` bookkeeping fields, which
    routinely exceed it. Nothing written through `JsonState` is signed --
    signed records are canonicalized once, explicitly, by `sign()`/`verify()`
    before they ever reach here.
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_plain_json(value) + b"\n")
    os.replace(temporary, path)
    os.chmod(path, 0o600)


class JsonState:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def get(self, name: str, default: Any) -> Any:
        path = self.directory / name
        with self.lock:
            if not path.exists():
                return default
            return json.loads(path.read_text(encoding="utf-8"))

    def put(self, name: str, value: Any) -> None:
        with self.lock:
            atomic_json(self.directory / name, value)

    def append_jsonl(self, name: str, value: dict[str, Any]) -> None:
        path = self.directory / name
        with self.lock, path.open("a", encoding="utf-8") as output:
            output.write(_plain_json(value).decode() + "\n")
        os.chmod(path, 0o600)

    def read_jsonl(self, name: str) -> list[dict[str, Any]]:
        path = self.directory / name
        with self.lock:
            if not path.exists():
                return []
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class SafeAdapter(Protocol):
    """Model integration boundary. It never receives raw peer authority."""

    def capabilities(self) -> list[dict[str, Any]]: ...

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]: ...


class DefaultSafeAdapter:
    """Safe example adapter suitable for tests and initial deployments."""

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 5, "network": "none"},
            {"id": "coordinate.chat.v1", "risk": "observe", "max_runtime_s": 5, "network": "none"},
        ]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        capability = intent.get("capability")
        if capability == "observe.system.status.v1":
            return {"status": "ok", "summary": "Endpoint is online; no private host data exposed."}
        if capability == "coordinate.chat.v1":
            return {"status": "ok", "summary": str(intent.get("objective", ""))[:500]}
        raise FaspError("capability.unavailable", "Capability is not enabled by this adapter.")


class FaspHarness:
    """Durable FASP state machine behind the HTTP server."""

    def __init__(
        self,
        state_dir: Path,
        display_name: str,
        base_url: str,
        adapter: SafeAdapter | None = None,
        rate_limit_per_second: float = 10.0,
        rate_limit_burst: int = 20,
        safety_gate: LocalSafetyGate | None = None,
        adapter_concurrency: int = DEFAULT_ADAPTER_CONCURRENCY,
        max_inflight_tasks: int = DEFAULT_MAX_INFLIGHT_TASKS,
        supervisor: SafetySupervisor | None = None,
        missions: MissionService | None = None,
        layer_guard: LayerGuard | None = None,
    ) -> None:
        # JsonState still backs receipts.json and the admin_token file --
        # everything else (peers, tasks, grants, streams, reservations,
        # artifacts) is on SQLite as of Phase 7.
        self.state = JsonState(state_dir)
        self.identity = Identity.load_or_create(state_dir / "identity.json")
        self.db = Database(state_dir / "fasp.db")
        self.audit = AuditChain(self.db, self.identity.system_id)
        self.peers = PeersRepo(self.db, self.audit)
        self.inbox = InboxRepo(self.db)
        self.tasks = TasksRepo(self.db, self.audit)
        self.grants = GrantsRepo(self.db, self.audit)
        self.revocations = RevocationsRepo(self.db, self.audit)
        self.artifacts = ArtifactStore(self.db, state_dir)
        self.rate_limiter = TokenBucketLimiter(rate_limit_per_second, rate_limit_burst)
        self.metrics = MetricsRegistry()
        self.display_name = display_name
        self.base_url = base_url.rstrip("/")
        self.adapter = adapter or DefaultSafeAdapter()
        # The layer invariant is checked HERE, before a socket is bound: an
        # adapter exposing a Layer 1 function fails startup rather than
        # failing an audit six months later (see fasp_harness/layers.py).
        self.layer_guard = layer_guard or LayerGuard()
        self.capability_declarations = {declaration.id: declaration for declaration in self.layer_guard.validate_adapter(self.adapter.capabilities())}
        self.streams = StreamRegistry(StreamsRepo(self.db))
        self.reservations = ReservationBook(ReservationsRepo(self.db))
        self.safety_gate = safety_gate
        # Layers 1-3 integration, all optional: a plain coordination node
        # runs with none of them, and every handler below reports
        # `capability.unavailable` rather than pretending.
        self.supervisor = supervisor
        self.missions = missions
        # Bounded adapter work queue (ss7, ss15 #5/#6): every intent.propose
        # submits adapter.handle() here rather than calling it inline, which
        # buys three things a single synchronous call never had -- a real
        # wall-clock timeout on the requester's wait (Python cannot preempt
        # a hung thread, but it can stop waiting on one), a hard concurrency
        # bound (adapter_concurrency workers, not one thread per in-flight
        # HTTP request), and durable admission control: max_inflight_tasks
        # is enforced against the `tasks` table itself (see
        # TasksRepo.count_inflight), so the backlog bound survives a
        # restart instead of living only in process memory.
        self._executor = ThreadPoolExecutor(max_workers=adapter_concurrency, thread_name_prefix="fasp-adapter")
        self.max_inflight_tasks = max_inflight_tasks
        # Live push channels (websockets); see channels.py -- an
        # optimization layered on the durable queue above, never a
        # replacement for it.
        self.channels = ConnectionRegistry()
        if not (state_dir / "admin_token").exists():
            token = secrets.token_urlsafe(32)
            (state_dir / "admin_token").write_text(token + "\n", encoding="utf-8")
            os.chmod(state_dir / "admin_token", 0o600)
        # A row can only still be RUNNING here if the previous process
        # crashed mid-adapter-call; resolve it to a safe terminal state
        # rather than silently leaving it stuck (ss7.1, ss10, ss15 #5/#6).
        self.tasks.expire_stale_leases(stamp())

    @property
    def admin_token(self) -> str:
        return (self.state.directory / "admin_token").read_text(encoding="utf-8").strip()

    def close(self) -> None:
        """Graceful shutdown: stop accepting new adapter work and let
        in-flight calls finish before the process exits (ss15 #5/#6 --
        an abrupt kill is what the lease-expiry sweep on next startup
        exists to recover from; this path exists so a clean shutdown
        doesn't need that recovery in the first place)."""
        self._executor.shutdown(wait=True, cancel_futures=False)

    def id_card(self) -> dict[str, Any]:
        card = {
            "fasp": PROTOCOL,
            "type": "id_card",
            "system_id": self.identity.system_id,
            "display_name": self.display_name,
            "runtime": runtime_profile(),
            "public_key": self.identity.public_b64,
            "endpoints": {
                "profile": self.base_url + "/profile",
                "pair_hello": self.base_url + "/pair/hello",
                "envelopes": self.base_url + "/fasp/v1/envelopes",
                "receipts": self.base_url + "/fasp/v1/receipts",
                "channel": self.base_url.replace("https://", "wss://").replace("http://", "ws://") + "/fasp/v1/channel",
            },
            "capabilities": self.adapter.capabilities(),
            # Published so a peer can see, before sending anything, which
            # layers this system implements and which it only observes.
            "layers": describe_layers(),
            "issued_at": stamp(),
            "expires_at": stamp(now() + timedelta(days=30)),
        }
        return sign(card, self.identity.private, self.identity.kid)

    @staticmethod
    def verify_id_card(card: dict[str, Any]) -> None:
        required = {"fasp", "type", "system_id", "public_key", "endpoints", "expires_at", "signature"}
        if not required.issubset(card) or card.get("fasp") != PROTOCOL or card.get("type") != "id_card":
            raise FaspError("schema.invalid", "Invalid FASP ID card.")
        if parse_stamp(card["expires_at"]) <= now():
            raise FaspError("auth.card_expired", "ID card has expired.")
        verify(card, card["public_key"])
        raw = unb64(card["public_key"])
        expected = "fasp:system:" + b64(hashlib.sha256(raw).digest())
        if card["system_id"] != expected:
            raise FaspError("auth.identity_mismatch", "ID card identity does not match its public key.")

    def hello(self, card: dict[str, Any]) -> dict[str, Any]:
        self.verify_id_card(card)
        if card["system_id"] == self.identity.system_id:
            raise FaspError("auth.self_pairing", "A system cannot pair with itself.")
        fingerprint = b64(hashlib.sha256("|".join(sorted([self.identity.system_id, card["system_id"]])).encode()).digest())[:12]
        peer = self.peers.upsert_pending_or_seen(card["system_id"], card, fingerprint, stamp(), ["observe.", "coordinate."])
        return sign({"fasp": PROTOCOL, "type": "hello.ready", "system_id": self.identity.system_id, "id_card": self.id_card(), "pair_code": fingerprint, "pairing_required": peer["state"] != "paired", "issued_at": stamp()}, self.identity.private, self.identity.kid)

    def confirm_peer(self, peer_id: str, pair_code: str, prefixes: list[str] | None = None) -> dict[str, Any]:
        expires_at = stamp(now() + PEER_PAIRING_VALIDITY)
        peer = self.peers.confirm(peer_id, pair_code, stamp(), expires_at, prefixes)
        if peer is None:
            raise FaspError("auth.pairing_not_found", "Peer or pair code is invalid.")
        return {"ok": True, "peer_id": peer_id, "state": "paired", "expires_at": expires_at, "allowed_capability_prefixes": peer["allowed_capability_prefixes"]}

    def revoke_peer(self, peer_id: str, reason: str, revocation_ref: str | None = None) -> dict[str, Any]:
        """Immediately reject `peer_id` regardless of its pairing state.

        Per ss12: "On suspected key compromise, a system MUST stop
        accepting grants bound to that key ... and require re-pairing."
        Re-pairing (`confirm_peer`) is what clears this.
        """
        self.revocations.revoke(peer_id, stamp(), reason, revocation_ref)
        return {"ok": True, "peer_id": peer_id, "revoked": True}

    def _peer(self, peer_id: str) -> dict[str, Any]:
        if self.revocations.is_revoked(peer_id):
            raise FaspError("auth.peer_revoked", "Peer's identity has been revoked; re-pairing is required.")
        peer = self.peers.get(peer_id)
        if not peer or peer.get("state") != "paired":
            raise FaspError("auth.not_paired", "Peer is not paired and authorized.")
        if peer.get("expires_at") and parse_stamp(peer["expires_at"]) <= now():
            raise FaspError("auth.pairing_expired", "Peer's pairing has expired; re-pairing is required.")
        return peer

    def issue_grant(
        self,
        subject_peer: str,
        capability_prefixes: list[str],
        duration: timedelta,
        purpose: str | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Issue a time-limited, scoped grant to an already-paired peer (ss6, ss8).

        Grants are issued locally (by whoever holds the admin token, i.e.
        this system's own operating principal), not requested over the
        network -- there is no remote `grant.request` handler here, only
        the local decision to hand one out.
        """
        if not self.peers.get(subject_peer):
            raise FaspError("schema.invalid", "Cannot issue a grant to an unknown peer.")
        issued = now()
        return self.grants.issue(
            grant_id="grant-" + secrets.token_urlsafe(12),
            issuer=self.identity.system_id,
            subject_peer=subject_peer,
            capability_prefixes=capability_prefixes,
            issued_at=stamp(issued),
            expires_at=stamp(issued + duration),
            purpose=purpose,
            constraints=constraints,
        )

    def revoke_grant(self, grant_id: str) -> dict[str, Any]:
        if not self.grants.revoke(grant_id, stamp()):
            raise FaspError("schema.invalid", "Grant does not exist or is already revoked.")
        return {"ok": True, "grant_id": grant_id, "revoked": True}

    def make_envelope(self, kind: str, to: str, payload: dict[str, Any], conversation_id: str | None = None, causation_id: str | None = None) -> dict[str, Any]:
        issued = now()
        envelope = {
            "fasp": PROTOCOL,
            "kind": kind,
            "message_id": str(uuid.uuid4()),
            "conversation_id": conversation_id or str(uuid.uuid4()),
            "causation_id": causation_id,
            "from": self.identity.system_id,
            "to": to,
            "issued_at": stamp(issued),
            "expires_at": stamp(issued + timedelta(minutes=2)),
            "nonce": b64(secrets.token_bytes(12)),
            "payload": payload,
        }
        return sign(envelope, self.identity.private, self.identity.kid)

    def _verify_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Schema, audience, timing, signature, and per-peer rate limit only
        -- kind support/dispatch is `accept()`'s job, not this method's, so
        there is exactly one place that decides what a `kind` means."""
        required = {"fasp", "kind", "message_id", "from", "to", "issued_at", "expires_at", "nonce", "payload", "signature"}
        if not required.issubset(envelope) or envelope.get("fasp") != PROTOCOL:
            raise FaspError("schema.invalid", "Envelope misses required FASP fields.")
        if envelope["to"] != self.identity.system_id:
            raise FaspError("auth.wrong_audience", "Envelope is addressed to another system.")
        try:
            issued, expires = parse_stamp(envelope["issued_at"]), parse_stamp(envelope["expires_at"])
        except (TypeError, ValueError) as exc:
            raise FaspError("schema.invalid", "Envelope timestamps are invalid.") from exc
        if expires <= now() or issued > now() + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            raise FaspError("auth.envelope_expired", "Envelope is expired or issued too far in the future.")
        if len(_plain_json(envelope)) > MAX_INLINE_BYTES:
            raise FaspError("resource.too_large", "Inline envelope exceeds 64 KiB.")
        peer = self._peer(envelope["from"])
        verify(envelope, peer["card"]["public_key"])
        # Rate-limited by authenticated peer_id, after signature verification
        # -- an unauthenticated flood is the transport layer's job (ss10);
        # this is the per-relationship budget once we know who is asking.
        if not self.rate_limiter.allow(envelope["from"]):
            self.metrics.increment("fasp_rate_limited_total")
            raise FaspError("resource.exhausted", "Peer exceeded its request rate limit.")
        return peer

    # kind -> bound handler method name, `(envelope, peer) -> dict`. This is
    # the ONE dispatch table for the whole protocol -- every transport
    # (HTTP POST, the websocket channel) and every public per-kind method
    # below (`stream_open`, `heartbeat`, ...) all funnel through `accept()`,
    # so kind support, auth, and replay-dedup are decided in exactly one
    # place regardless of which door an envelope came in through.
    DISPATCH: dict[str, str] = {
        "intent.propose": "_handle_intent",
        "task.cancel": "_handle_cancel",
        "task.status": "_handle_task_status",
        "artifact.fetch": "_handle_artifact_fetch",
        "inbox.pull": "_handle_pull_inbox",
        "receipt.processed": "_handle_receipt",
        "stream.open": "_handle_stream_open",
        "stream.packet": "_handle_stream_packet",
        "stream.pull": "_handle_stream_pull",
        "stream.subscribe": "_handle_stream_subscribe",
        "stream.unsubscribe": "_handle_stream_unsubscribe",
        "stream.close": "_handle_stream_close",
        "reservation.request": "_handle_reservation_request",
        "reservation.release": "_handle_reservation_release",
        "safety.halt": "_handle_safety_halt",
        "safety.status": "_handle_safety_status",
        "safety.evidence": "_handle_safety_evidence",
        "mission.dispatch": "_handle_mission_dispatch",
        "mission.cancel": "_handle_mission_cancel",
        "mission.status": "_handle_mission_status",
        "fleet.status": "_handle_fleet_status",
        "incident.report": "_handle_report_incident",
        "heartbeat": "_handle_heartbeat",
    }

    def accept(self, envelope: dict[str, Any], expected_kind: str | None = None) -> tuple[bool, dict[str, Any] | None]:
        """Verify, dedup, and dispatch any envelope kind in `DISPATCH`.

        `expected_kind` narrows acceptance to one specific kind (used by the
        dedicated `/fasp/v1/receipts` route, and by every per-kind wrapper
        method below) -- it is a stricter gate on top of `DISPATCH`, never a
        substitute for it, so an unsupported kind is still rejected even
        when no `expected_kind` is given.

        Replay dedup (ss5, ss7.1) applies uniformly to every kind here, not
        only `intent.propose`: a network retry of, say, `stream.packet` or
        `reservation.request` with the same `message_id` returns the
        original recorded response instead of re-applying its effect a
        second time.
        """
        peer = self._verify_envelope(envelope)
        kind = envelope["kind"]
        if expected_kind is not None and kind != expected_kind:
            raise FaspError("protocol.unsupported_kind", f"Endpoint requires {expected_kind}.")
        handler_name = self.DISPATCH.get(kind)
        if handler_name is None:
            raise FaspError("protocol.unsupported_kind", f"Unsupported envelope kind: {kind!r}.")
        self.metrics.increment("fasp_envelopes_total", kind=kind)
        if not self.inbox.insert_if_new(envelope, stamp()):
            return True, self.inbox.get_response(envelope["message_id"])
        try:
            response = getattr(self, handler_name)(envelope, peer)
        except FaspError as error:
            # Recorded (not just raised) so a replay of this exact envelope
            # returns the same rejection deterministically instead of
            # re-running the check -- see the ss7.1 idempotent-handling note
            # in _handle_intent for why this matters at the task level too.
            self.inbox.set_response(envelope["message_id"], {"type": "protocol.error", "error": {"code": error.code, "detail": error.detail}})
            raise
        self.inbox.set_response(envelope["message_id"], response)
        return False, response

    def _handle_intent(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        intent = envelope["payload"]
        key = intent.get("idempotency_key")
        capability = intent.get("capability", "")
        if not isinstance(key, str) or not key or not isinstance(capability, str):
            raise FaspError("schema.invalid", "Intent requires idempotency_key and capability.")
        if not any(capability.startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Paired peer is not granted this capability prefix.")

        # Durable backpressure (ss15 #8): the `tasks` table itself is this
        # queue's depth counter, so the bound holds across a restart rather
        # than resetting with an in-memory one -- a saturated backlog is
        # rejected up front instead of growing without limit.
        if self.tasks.count_inflight() >= self.max_inflight_tasks:
            raise FaspError("resource.exhausted", "Task queue is at capacity; retry later.")

        # Creation of the PROPOSED row is what makes this idempotent (ss7.1):
        # a duplicate of the same idempotency_key can never race past this
        # point twice, and a duplicate arriving on a later request always
        # finds the first one already terminal (or still genuinely in
        # flight on the adapter pool, in which case it is told to wait).
        if not self.tasks.propose(key, intent.get("intent_id"), capability, envelope["from"], stamp()):
            existing = self.tasks.get(key)
            if existing is not None and existing["state"] == "REJECTED":
                error = existing["error"] or {}
                raise FaspError(error.get("code", "policy.requires_confirmation"), error.get("detail", "Intent was previously rejected."))
            if existing is not None and existing["state"] in TERMINAL_STATES:
                return _task_response(existing)
            raise FaspError("schema.invalid", "idempotency_key is already in use by a request still being processed.")

        capabilities = {item["id"]: item for item in self.adapter.capabilities()}
        if capability not in capabilities:
            self._reject_task(key, "capability.unavailable", "Capability is unavailable at this runtime.")
        # Re-checked here, not only at startup: an adapter may compute its
        # capability list per call, and the layer boundary is not something
        # to enforce once and hope stays enforced.
        try:
            self.layer_guard.check_capability(self.capability_declarations.get(capability) or CapabilityDeclaration.from_mapping(capabilities[capability]))
        except FaspError as error:
            self._reject_task(key, error.code, error.detail)
        risk = intent.get("risk", capabilities[capability]["risk"])
        if not capability_policy.is_executable(risk):
            self._reject_task(key, "policy.requires_confirmation", "This harness requires explicit local approval for this risk class.")
        grant_id = intent.get("grant", {}).get("id") if isinstance(intent.get("grant"), dict) else None
        try:
            validate_grant_if_required(self.grants, envelope["from"], capability, grant_id, capability_policy.requires_grant(risk))
        except FaspError as error:
            self._reject_task(key, error.code, error.detail)

        max_runtime_s = capabilities[capability].get("max_runtime_s")
        lease_seconds = float(max_runtime_s) if isinstance(max_runtime_s, (int, float)) and max_runtime_s > 0 else DEFAULT_TASK_LEASE.total_seconds()
        if not self.tasks.start_running(key, stamp(now() + timedelta(seconds=lease_seconds)), stamp()):
            # Lost a race to a concurrent task.cancel that reached the row
            # first (PROPOSED -> CANCELLED); report that outcome, not ours.
            return _task_response(self.tasks.get(key))

        return self._run_adapter_bounded(key, intent, envelope["from"], lease_seconds)

    def _run_adapter_bounded(self, key: str, intent: dict[str, Any], from_peer: str, lease_seconds: float) -> dict[str, Any]:
        """Run `adapter.handle()` on the bounded pool, capped at the
        capability's own declared `max_runtime_s` (ss7.1, ss15 #5/#6).

        Python cannot forcibly preempt a hung synchronous call, so a
        timeout here does not kill the worker thread -- it stops the
        *caller* from waiting on it past the promised lease and returns
        `task.progress` instead of blocking the connection indefinitely.
        The future keeps running regardless.

        The done-callback that commits and pushes a late result is
        registered ONLY once a timeout has actually happened, not
        unconditionally up front: `add_done_callback` runs immediately
        (synchronously, in whichever thread calls it) if the future is
        already finished, and otherwise runs later when it does -- either
        way, registering it after the timeout, rather than racing it
        against this method's own `future.result()`, means the fast path
        (the overwhelming common case) never pushes a redundant `task.push`
        for a result its caller is about to receive directly anyway.
        """
        intent_id = intent.get("intent_id")
        future = self._executor.submit(self.adapter.handle, intent)
        try:
            output = future.result(timeout=lease_seconds)
        except FutureTimeoutError:
            future.add_done_callback(lambda done: self._on_adapter_done(key, from_peer, intent_id, done))
            return {"type": "task.progress", "idempotency_key": key, "status": "running", "detail": "Exceeded the capability's synchronous wait; poll task.status or await a pushed result."}
        except FaspError as error:
            return self._apply_task_outcome(key, from_peer, intent_id, error={"code": error.code, "detail": error.detail}, push=False)
        except Exception:
            # Never let an adapter bug leak a raw traceback to a peer (ss12);
            # a broken adapter fails the task, it doesn't crash the request.
            return self._apply_task_outcome(key, from_peer, intent_id, error={"code": "internal.adapter_error", "detail": "Adapter raised an unexpected error."}, push=False)
        return self._apply_task_outcome(key, from_peer, intent_id, output=output, push=False)

    def _on_adapter_done(self, key: str, from_peer: str, intent_id: str | None, future: Any) -> None:
        """The done-callback registered only after `_run_adapter_bounded`
        has already timed out -- commits and pushes a result that its
        original caller stopped waiting for."""
        exception = future.exception()
        if exception is None:
            self._apply_task_outcome(key, from_peer, intent_id, output=future.result())
        elif isinstance(exception, FaspError):
            self._apply_task_outcome(key, from_peer, intent_id, error={"code": exception.code, "detail": exception.detail})
        else:
            self._apply_task_outcome(key, from_peer, intent_id, error={"code": "internal.adapter_error", "detail": "Adapter raised an unexpected error."})

    def _apply_task_outcome(self, key: str, from_peer: str, intent_id: str | None, *, output: Any = None, error: dict[str, Any] | None = None, push: bool = True) -> dict[str, Any]:
        if error is not None:
            result = {"type": "task.fail", "intent_id": intent_id, "idempotency_key": key, "status": "failed", "error": error, "completed_at": stamp()}
            committed = self.tasks.fail(key, error, stamp())
        else:
            result = {"type": "task.result", "intent_id": intent_id, "idempotency_key": key, "status": "completed", "completed_at": stamp()}
            result.update(self._materialize_output(output, from_peer))
            committed = self.tasks.complete(key, result, stamp())
        if not committed:
            # A concurrent task.cancel already moved the row to its
            # authoritative final state; report that, not the outcome just
            # computed.
            return _task_response(self.tasks.get(key))
        if push:
            self.channels.push(from_peer, {"fasp": PROTOCOL, "type": "task.push", "response": result})
        return result

    def _reject_task(self, key: str, code: str, detail: str) -> NoReturn:
        self.tasks.reject(key, {"code": code, "detail": detail}, stamp())
        raise FaspError(code, detail)

    def _materialize_output(self, output: Any, created_by: str) -> dict[str, Any]:
        """Inline `output` unless it's too big for a signed 64 KiB envelope
        (ss5), in which case store it as an immutable artifact (ss11) and
        return a digest reference instead."""
        encoded = _plain_json(output)
        if len(encoded) <= ARTIFACT_INLINE_THRESHOLD_BYTES:
            return {"output": output}
        artifact = self.artifacts.put(encoded, "application/json", created_by, stamp(), ARTIFACT_RETENTION)
        return {"artifact": {"artifact_id": artifact["artifact_id"], "digest": artifact["digest"], "media_type": artifact["media_type"], "size_bytes": artifact["size_bytes"]}}

    def _handle_artifact_fetch(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del peer
        artifact_id = envelope["payload"].get("artifact_id")
        if not isinstance(artifact_id, str):
            raise FaspError("schema.invalid", "artifact.fetch requires artifact_id.")
        artifact = self.artifacts.get(artifact_id)
        if artifact is None:
            raise FaspError("schema.invalid", "Unknown artifact_id.")
        data = self.artifacts.read_bytes(artifact_id)
        if data is None or len(data) > MAX_INLINE_BYTES:
            raise FaspError("resource.too_large", "Artifact exceeds inline transfer size; use an out-of-band transfer.")
        return {"artifact_id": artifact_id, "media_type": artifact["media_type"], "digest": artifact["digest"], "payload": b64(data)}

    def _handle_cancel(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """task.cancel: cancel-before-effect vs cancel-too-late (ss7.2, ss15 #7).

        `peer` (the caller) must be the same peer the task was proposed by
        -- cancellation is not a capability any paired peer gets to invoke
        on any task.
        """
        del peer
        key = envelope["payload"].get("idempotency_key")
        if not isinstance(key, str) or not key:
            raise FaspError("schema.invalid", "task.cancel requires idempotency_key.")
        task = self.tasks.get(key)
        if task is None:
            raise FaspError("schema.invalid", "Unknown idempotency_key.")
        if task["from_peer"] != envelope["from"]:
            raise FaspError("auth.not_authorized", "Only the proposing peer may cancel this task.")

        if self.tasks.cancel_immediately(key, stamp()):
            return {"type": "task.cancelled", "idempotency_key": key}

        task = self.tasks.get(key)
        if task["state"] == "RUNNING" and self.tasks.request_cancel(key, stamp()):
            cancel_hook = getattr(self.adapter, "cancel", None)
            accepted = bool(cancel_hook(key)) if callable(cancel_hook) else False
            if accepted and self.tasks.cancel_immediately(key, stamp()):
                return {"type": "task.cancelled", "idempotency_key": key}
            self.tasks.resume_running(key, stamp())
            task = self.tasks.get(key)

        if task["state"] == "CANCELLED":
            return {"type": "task.cancelled", "idempotency_key": key}
        return {"type": "task.too_late", "idempotency_key": key, "status": task["state"].lower(), "outcome": _task_response(task)}

    def _handle_task_status(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """Poll an intent.propose's outcome by idempotency_key (ss7.1, ss15
        #5/#6) -- the counterpart to a pushed `task.push` for a peer with no
        open channel, or one that simply wants to check back later."""
        del peer
        key = envelope["payload"].get("idempotency_key")
        if not isinstance(key, str) or not key:
            raise FaspError("schema.invalid", "task.status requires idempotency_key.")
        task = self.tasks.get(key)
        if task is None or task["from_peer"] != envelope["from"]:
            raise FaspError("schema.invalid", "Unknown idempotency_key.")
        return _task_response(task)

    def pull_inbox(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="inbox.pull")
        return response

    def _handle_pull_inbox(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del peer
        cursor = float(envelope["payload"].get("cursor", 0))
        messages = self.inbox.pull_since(envelope["from"], cursor)
        return {"messages": messages, "cursor": now().timestamp()}

    def receipt(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="receipt.processed")
        return response

    def _handle_receipt(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del peer
        payload = envelope["payload"]
        if not isinstance(payload.get("message_id"), str):
            raise FaspError("schema.invalid", "Receipt requires message_id.")
        receipts = self.state.get("receipts.json", {})
        receipts[payload["message_id"]] = {"from": envelope["from"], "processed_at": stamp()}
        self.state.put("receipts.json", receipts)
        return {"ok": True}

    def _authorize_stream(self, envelope: dict[str, Any], peer: dict[str, Any]) -> None:
        capability = envelope["payload"].get("capability", "observe.stream.v1")
        if not isinstance(capability, str) or not any(capability.startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Paired peer is not authorized for this stream capability.")

    def stream_open(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="stream.open")
        return response

    def _handle_stream_open(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        self._authorize_stream(envelope, peer)
        return self.streams.open(envelope["from"], envelope["payload"])

    def stream_packet(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="stream.packet")
        return response

    def _handle_stream_packet(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        self._authorize_stream(envelope, peer)
        payload = envelope["payload"]
        ack = self.streams.packet(envelope["from"], payload)
        # Live push (ss13 streaming profile): a genuinely new (non-
        # duplicate, non-retransmit) packet is fanned out immediately to
        # every subscriber with an open channel -- `stream.pull` remains
        # the durable, resumable backstop for whatever a dropped push
        # notification, or a subscriber with no open channel, misses.
        if not ack["duplicate"]:
            stream_id = payload["stream_id"]
            message = {"fasp": PROTOCOL, "type": "stream.push", "stream_id": stream_id, "packet": payload}
            for subscriber in self.streams.subscribers_of(stream_id):
                self.channels.push(subscriber, message)
        return ack

    def stream_pull(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="stream.pull")
        return response

    def _handle_stream_pull(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        self._authorize_stream(envelope, peer)
        payload = envelope["payload"]
        if not isinstance(payload.get("stream_id"), str):
            raise FaspError("schema.invalid", "stream.pull requires stream_id.")
        return self.streams.pull(envelope["from"], payload["stream_id"], int(payload.get("after_sequence", -1)))

    def stream_subscribe(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="stream.subscribe")
        return response

    def _handle_stream_subscribe(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """Opt in to live push delivery of a stream's future packets over
        this peer's open channel (see channels.py) -- a subscription with
        no open channel simply receives nothing until one exists; it is
        never an error, and `stream.pull` always still works regardless."""
        self._authorize_stream(envelope, peer)
        payload = envelope["payload"]
        if not isinstance(payload.get("stream_id"), str):
            raise FaspError("schema.invalid", "stream.subscribe requires stream_id.")
        return self.streams.subscribe(envelope["from"], payload["stream_id"])

    def stream_unsubscribe(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="stream.unsubscribe")
        return response

    def _handle_stream_unsubscribe(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del peer
        payload = envelope["payload"]
        if not isinstance(payload.get("stream_id"), str):
            raise FaspError("schema.invalid", "stream.unsubscribe requires stream_id.")
        return self.streams.unsubscribe(envelope["from"], payload["stream_id"])

    def stream_close(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="stream.close")
        return response

    def _handle_stream_close(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        self._authorize_stream(envelope, peer)
        payload = envelope["payload"]
        if not isinstance(payload.get("stream_id"), str):
            raise FaspError("schema.invalid", "stream.close requires stream_id.")
        return self.streams.close(envelope["from"], payload["stream_id"], str(payload.get("reason", "closed")))

    def reservation_request(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="reservation.request")
        return response

    def _handle_reservation_request(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        if not any("fleet.reserve.v1".startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Peer is not authorized for fleet reservations.")
        return self.reservations.request(envelope["from"], envelope["payload"])

    def reservation_release(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="reservation.release")
        return response

    def _handle_reservation_release(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        if not any("fleet.reserve.v1".startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", "Peer is not authorized for fleet reservations.")
        reservation_id = envelope["payload"].get("reservation_id")
        if not isinstance(reservation_id, str):
            raise FaspError("schema.invalid", "reservation.release requires reservation_id.")
        return self.reservations.release(envelope["from"], reservation_id)

    def safety_halt(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """A paired peer may REQUEST an emergency stop, never clear one (ss9.1).

        Honoring a halt request is always safe to do immediately; only
        local code (never a network handler) can call
        LocalSafetyGate.clear_halt().
        """
        _, response = self.accept(envelope, expected_kind="safety.halt")
        return response

    def _handle_safety_halt(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """Honour a halt request from a paired peer, everywhere it applies.

        A halt is the one thing this harness does eagerly and without
        further authorization: stopping is always safe, and a peer that
        can authenticate can always ask for it. Note the asymmetry with
        `safety.clear`, which does not exist as a message kind at all --
        clearing is local work at the machine, not a protocol operation
        (FASP_PROTOCOL.md ss9.1, and `fasp_harness/layers.py`).
        """
        del peer
        reason = str(envelope["payload"].get("reason", "halt requested by peer"))[:200]
        if self.supervisor is None and self.safety_gate is None:
            raise FaspError("capability.unavailable", "This system has no local safety-gated actuation to halt.")
        response: dict[str, Any] = {"type": "safety.status"}
        if self.supervisor is not None:
            demand = self.supervisor.demand_halt("peer:" + envelope["from"], reason, origin="peer")
            response.update({**self.supervisor.status(), "demand": demand.to_dict()})
        if self.safety_gate is not None:
            self.safety_gate.request_halt(reason)
            response.update(self.safety_gate.status())
        if self.missions is not None:
            # Ask every coordinated vehicle to stop as well. Best effort by
            # design: whether a vehicle acknowledges changes nothing about
            # the latch above, and nothing about its own protective stop.
            response["fleet"] = self.missions.halt_all(reason, source="peer:" + envelope["from"], origin="peer")["vehicles"]
        with self.db.write() as conn:
            self.audit.append(conn, "safety.halt_requested", envelope["from"], {"reason": reason}, stamp())
        return response

    def safety_status(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="safety.status")
        return response

    def _handle_safety_status(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del envelope, peer
        if self.supervisor is not None:
            return {"type": "safety.status", **self.supervisor.status()}
        if self.safety_gate is None:
            raise FaspError("capability.unavailable", "This system has no local safety gate to report on.")
        return {"type": "safety.status", **self.safety_gate.status()}

    def safety_evidence(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="safety.evidence")
        return response

    def _handle_safety_evidence(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """Everything a peer may know about this system's Layer 1 relationship.

        Deliberately read-only and deliberately complete: which controller,
        whether it is real hardware, what integrity is claimed for it, which
        safety functions are declared, and the current state. A peer
        deciding whether to trust this system with coordination needs that;
        a peer can do nothing with it.
        """
        del envelope, peer
        if self.supervisor is None:
            raise FaspError("capability.unavailable", "This system observes no safety controller.")
        return self.supervisor.evidence()

    def _require_prefix(self, peer: dict[str, Any], capability: str) -> None:
        if not any(capability.startswith(prefix) for prefix in peer["allowed_capability_prefixes"]):
            raise FaspError("auth.not_authorized", f"Paired peer is not authorized for {capability!r}.")

    def mission_dispatch(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="mission.dispatch")
        return response

    def _handle_mission_dispatch(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """Accept goal-level Layer 3 work: a mission, not a trajectory.

        Everything that decides whether this is safe and sensible -- the
        safety latch, leadership, vehicle selection across vendors, twin
        preflight, space-time reservation -- happens in `MissionService`,
        in that order. This handler only authorizes and translates.
        """
        self._require_prefix(peer, "fleet.mission.v1")
        if self.missions is None:
            raise FaspError("capability.unavailable", "This system does not coordinate missions.")
        return self.missions.submit(Mission.from_dict(envelope["payload"], requested_by=envelope["from"]))

    def mission_cancel(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="mission.cancel")
        return response

    def _handle_mission_cancel(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        self._require_prefix(peer, "fleet.mission.v1")
        if self.missions is None:
            raise FaspError("capability.unavailable", "This system does not coordinate missions.")
        mission_id = envelope["payload"].get("mission_id")
        if not isinstance(mission_id, str) or not mission_id:
            raise FaspError("schema.invalid", "mission.cancel requires mission_id.")
        return self.missions.cancel(mission_id, envelope["from"])

    def mission_status(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="mission.status")
        return response

    def _handle_mission_status(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        self._require_prefix(peer, "fleet.mission.v1")
        if self.missions is None:
            raise FaspError("capability.unavailable", "This system does not coordinate missions.")
        mission_id = envelope["payload"].get("mission_id")
        if not isinstance(mission_id, str) or not mission_id:
            raise FaspError("schema.invalid", "mission.status requires mission_id.")
        record = self.missions.status(mission_id)
        if record.get("mission_id") and self.missions.missions.get(mission_id)["requested_by"] != envelope["from"]:
            raise FaspError("auth.not_authorized", "Only the requesting peer may read this mission.")
        return record

    def _handle_fleet_status(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        """Layer 2/3 observation: what the fleet is doing, right now."""
        del envelope
        self._require_prefix(peer, "observe.fleet.v1")
        if self.missions is None:
            raise FaspError("capability.unavailable", "This system does not coordinate a fleet.")
        return {"type": "fleet.status", **self.missions.overview()}

    def report_incident(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Durably record an incident report (ss11); this harness does not
        interpret or act on it beyond that -- response is local operator work."""
        _, response = self.accept(envelope, expected_kind="incident.report")
        return response

    def _handle_report_incident(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del peer
        summary = str(envelope["payload"].get("summary", ""))[:500]
        with self.db.write() as conn:
            self.audit.append(conn, "incident.reported", envelope["from"], {"summary": summary}, stamp())
        return {"ok": True}

    def heartbeat(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Advisory liveness only (ss7.3) -- never task state, authorization,
        or safety evidence."""
        _, response = self.accept(envelope, expected_kind="heartbeat")
        return response

    def _handle_heartbeat(self, envelope: dict[str, Any], peer: dict[str, Any]) -> dict[str, Any]:
        del envelope, peer
        return {"type": "heartbeat", "server_time": stamp()}

    def task_status(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _, response = self.accept(envelope, expected_kind="task.status")
        return response
