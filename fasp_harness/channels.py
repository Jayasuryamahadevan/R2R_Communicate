"""In-memory registry of live, authenticated push channels (websockets).

This is deliberately NOT durable state: it is a best-effort optimization
layered on top of durable task/queue machinery in `core.py` and `storage/`.
Durable task consumers can poll after a dropped push. Explicit memory-only
stream observations have no replay and can be lost. Pending sends and
connections have fixed bounds; slow consumers cannot grow an unlimited queue.

Registering a connection and pushing a message happen on different
threads: registration happens on the asyncio event loop thread (inside a
websocket route handler), while a push is usually triggered from a
background adapter-pool worker thread finishing a task. `asyncio.
run_coroutine_threadsafe` is the documented way to hand a coroutine to a
loop running on another thread; `bind_loop` captures that loop once, at
ASGI startup.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable
from typing import Any, Protocol

from .protocol.errors import FaspError


class _Sendable(Protocol):
    async def send_text(self, data: str) -> None: ...


class ConnectionRegistry:
    def __init__(self, *, max_connections: int = 128, max_per_peer: int = 4, max_pending: int = 16, max_pending_bytes: int = 8 * 1024 * 1024, send_timeout_s: float = 1.0, authorize_peer: Callable[[str], Any] | None = None) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_connections, max_per_peer, max_pending, max_pending_bytes)) or not 0 < send_timeout_s <= 60:
            raise ValueError("Channel bounds must be positive and send timeout must be at most 60 seconds.")
        self.authorize_peer = authorize_peer
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connections: dict[str, set[_Sendable]] = {}
        self._pending: dict[_Sendable, int] = {}
        self._send_locks: dict[_Sendable, asyncio.Lock] = {}
        self.max_connections, self.max_per_peer, self.max_pending = max_connections, max_per_peer, max_pending
        self.send_timeout_s = send_timeout_s
        self.max_pending_bytes = max_pending_bytes
        self.pending_bytes = 0
        self.dropped = 0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Call once from an ASGI startup handler, on the running loop."""
        with self._lock:
            self._loop = loop

    def register(self, peer_id: str, connection: _Sendable) -> bool:
        with self._lock:
            if connection in self._connections.get(peer_id, ()):
                return True
            if connection in self._pending:
                return False
            if len(self._pending) >= self.max_connections or len(self._connections.get(peer_id, ())) >= self.max_per_peer:
                return False
            self._connections.setdefault(peer_id, set()).add(connection)
            self._pending[connection] = 0
            self._send_locks[connection] = asyncio.Lock()
            return True

    def unregister(self, peer_id: str, connection: _Sendable) -> None:
        with self._lock:
            live = self._connections.get(peer_id)
            if live is None:
                return
            live.discard(connection)
            # Keep reservations for already scheduled sends until their
            # finally blocks run. Reconnect churn cannot release the budget
            # while old coroutines still retain their frames.
            if not self._pending.get(connection):
                self._pending.pop(connection, None)
                self._send_locks.pop(connection, None)
            if not live:
                del self._connections[peer_id]

    def is_connected(self, peer_id: str) -> bool:
        with self._lock:
            return bool(self._connections.get(peer_id))

    def disconnect(self, peer_id: str) -> None:
        with self._lock:
            targets = list(self._connections.get(peer_id, ()))
            loop = self._loop
        for connection in targets:
            self.unregister(peer_id, connection)
            if loop is not None and not loop.is_closed():
                coroutine = self._close(connection)
                try:
                    asyncio.run_coroutine_threadsafe(coroutine, loop)
                except RuntimeError:
                    coroutine.close()

    async def _close(self, connection: _Sendable) -> None:
        close = getattr(connection, "close", None)
        if close is not None:
            try:
                async with asyncio.timeout(self.send_timeout_s):
                    await close(code=1013)
            except (Exception, asyncio.CancelledError):
                pass

    def push(self, peer_id: str, message: dict[str, Any]) -> bool:
        """Best-effort, fire-and-forget push from any thread.

        Returns True only if a live channel existed to target -- never a
        guarantee of delivery (the coroutine is merely scheduled; a
        connection can still drop before it runs). Callers must treat this
        purely as an optimization, never as proof the peer received it.
        """
        if not self.is_connected(peer_id):
            return False
        if self.authorize_peer is not None:
            try:
                self.authorize_peer(peer_id)
            except FaspError:
                self.disconnect(peer_id)
                return False
        try:
            wire = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            size = len(wire.encode("utf-8"))
        except (TypeError, ValueError, UnicodeError):
            return False
        with self._lock:
            loop = self._loop
            if loop is None or loop.is_closed():
                return False
            targets = []
            for connection in self._connections.get(peer_id, ()):
                if self._pending[connection] >= self.max_pending or self.pending_bytes + size > self.max_pending_bytes:
                    self.dropped += 1
                    continue
                self._pending[connection] += 1
                self.pending_bytes += size
                targets.append((connection, self._send_locks[connection]))
        if not targets:
            return False
        for connection, lock in targets:
            coroutine = self._send(peer_id, connection, lock, wire, size)
            try:
                asyncio.run_coroutine_threadsafe(coroutine, loop)
            except RuntimeError:
                coroutine.close()
                self.unregister(peer_id, connection)
                self._release(peer_id, connection, size)
        return True

    def _release(self, peer_id: str, connection: _Sendable, size: int) -> None:
        with self._lock:
            self._pending[connection] -= 1
            self.pending_bytes -= size
            if not self._pending[connection] and connection not in self._connections.get(peer_id, ()):
                self._pending.pop(connection)
                self._send_locks.pop(connection, None)

    async def _send(self, peer_id: str, connection: _Sendable, lock: asyncio.Lock, wire: str, size: int) -> None:
        try:
            async with asyncio.timeout(self.send_timeout_s):
                async with lock:
                    with self._lock:
                        connected = connection in self._connections.get(peer_id, ())
                    if connected:
                        await connection.send_text(wire)
        except Exception:
            # Failed/slow subscribers must not create an unbounded number of
            # waiting tasks. Durable consumers can poll; volatile data is lost.
            self.unregister(peer_id, connection)
            await self._close(connection)
        finally:
            self._release(peer_id, connection, size)
