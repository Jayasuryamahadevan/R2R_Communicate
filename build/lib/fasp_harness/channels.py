"""In-memory registry of live, authenticated push channels (websockets).

This is deliberately NOT durable state: it is a best-effort optimization
layered on top of the durable task/queue machinery in `core.py` and
`storage/`, not a replacement for it. A peer with no open channel simply
falls back to polling (`task.status`) or discovers the result the next
time it opens one -- nothing is ever lost by a missing or dropped
connection, only delivered later instead of immediately.

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
import threading
from typing import Any, Protocol


class _Sendable(Protocol):
    async def send_json(self, data: Any) -> None: ...


class ConnectionRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connections: dict[str, set[_Sendable]] = {}

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Call once from an ASGI startup handler, on the running loop."""
        with self._lock:
            self._loop = loop

    def register(self, peer_id: str, connection: _Sendable) -> None:
        with self._lock:
            self._connections.setdefault(peer_id, set()).add(connection)

    def unregister(self, peer_id: str, connection: _Sendable) -> None:
        with self._lock:
            live = self._connections.get(peer_id)
            if live is None:
                return
            live.discard(connection)
            if not live:
                del self._connections[peer_id]

    def is_connected(self, peer_id: str) -> bool:
        with self._lock:
            return bool(self._connections.get(peer_id))

    def push(self, peer_id: str, message: dict[str, Any]) -> bool:
        """Best-effort, fire-and-forget push from any thread.

        Returns True only if a live channel existed to target -- never a
        guarantee of delivery (the coroutine is merely scheduled; a
        connection can still drop before it runs). Callers must treat this
        purely as an optimization, never as proof the peer received it.
        """
        with self._lock:
            loop = self._loop
            targets = list(self._connections.get(peer_id, ()))
        if not targets or loop is None:
            return False
        for connection in targets:
            asyncio.run_coroutine_threadsafe(connection.send_json(message), loop)
        return True
