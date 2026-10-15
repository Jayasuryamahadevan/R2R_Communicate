"""Bounded transport execution and one writer per full-duplex connection."""

from __future__ import annotations

import asyncio
import json
import math
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass
from typing import Any

from ..protocol.errors import FaspError

CONTROL_KINDS = frozenset(
    {
        "task.status",
        "task.cancel",
        "stream.close",
        "reservation.release",
        "receipt.processed",
        "safety.halt",
        "safety.status",
        "mission.status",
        "mission.cancel",
    }
)
OBSERVATION_KINDS = frozenset({"heartbeat", "stream.packet"})


@dataclass(frozen=True)
class TransportLimits:
    work_workers: int = 8
    control_workers: int = 4
    observation_workers: int = 4
    per_peer_per_lane: int = 2
    max_channels: int = 128
    auth_timeout_s: float = 5.0
    body_timeout_s: float = 10.0
    max_invalid_frames: int = 8
    send_timeout_s: float = 1.0

    def __post_init__(self) -> None:
        for name in ("work_workers", "control_workers", "observation_workers", "per_peer_per_lane", "max_invalid_frames"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 64:
                raise ValueError(f"{name} must be an integer from 1 to 64.")
        if isinstance(self.max_channels, bool) or not isinstance(self.max_channels, int) or not 1 <= self.max_channels <= 128:
            raise ValueError("max_channels must be an integer from 1 to 128.")
        if self.work_workers + self.control_workers + self.observation_workers > 128:
            raise ValueError("Total ingress workers cannot exceed 128.")
        for name in ("auth_timeout_s", "body_timeout_s", "send_timeout_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 60:
                raise ValueError(f"{name} must be finite, positive and at most 60 seconds.")


class IngressDispatcher:
    """No waiting queue. Reserve before submission, release in the worker.

    Peer claims only partition capacity; they never grant authority. A cancelled
    caller retains its reservation until its synchronous handler really exits.
    """

    def __init__(self, limits: TransportLimits, metrics) -> None:
        self.limits = limits
        self.metrics = metrics
        self._lock = threading.Lock()
        self._closed = False
        self._pools = {
            name: ThreadPoolExecutor(max_workers=count, thread_name_prefix=f"fasp-{name}")
            for name, count in (
                ("work", limits.work_workers),
                ("control", limits.control_workers),
                ("observation", limits.observation_workers),
            )
        }
        self._active = dict.fromkeys(self._pools, 0)
        self._peers: dict[tuple[str, str], int] = {}

    @staticmethod
    def lane(envelope: dict[str, Any]) -> str:
        kind = envelope.get("kind")
        if not isinstance(kind, str):
            return "work"
        return "observation" if kind in OBSERVATION_KINDS else "control" if kind in CONTROL_KINDS else "work"

    async def run(self, envelope: dict[str, Any], function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        lane = self.lane(envelope)
        peer = envelope.get("from")
        # Bound even unvalidated claims retained by an in-flight reservation.
        peer = peer if isinstance(peer, str) and len(peer) <= 128 else "unknown"
        key = (lane, peer)
        with self._lock:
            if (
                self._closed
                or self._active[lane] >= getattr(self.limits, f"{lane}_workers")
                or self._peers.get(key, 0) >= self.limits.per_peer_per_lane
            ):
                self.metrics.increment("fasp_ingress_rejected_total", lane=lane)
                raise FaspError("transport.overloaded", "Ingress capacity is busy; retry with backoff and the same message ID.")
            self._active[lane] += 1
            self._peers[key] = self._peers.get(key, 0) + 1
            try:
                future = self._pools[lane].submit(copy_context().run, self._execute, key, function)
            except BaseException:
                self._release(key)
                raise
        wrapped = asyncio.wrap_future(future)
        # Retrieve failures even when the client has disconnected meanwhile.
        wrapped.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        return await asyncio.shield(wrapped)

    def _execute(self, key: tuple[str, str], function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return function()
        finally:
            with self._lock:
                self._release(key)

    def _release(self, key: tuple[str, str]) -> None:
        self._active[key[0]] -= 1
        self._peers[key] -= 1
        if not self._peers[key]:
            del self._peers[key]

    def gauges(self) -> dict[str, int]:
        with self._lock:
            return {f'fasp_ingress_active{{lane="{lane}"}}': count for lane, count in self._active.items()}

    def close(self) -> None:
        with self._lock:
            self._closed = True
        for pool in self._pools.values():
            pool.shutdown(wait=True)


class ChannelSession:
    """Replies, pushes and close share one lock and a finite send deadline."""

    def __init__(self, websocket, timeout_s: float) -> None:
        self.websocket = websocket
        self.timeout_s = timeout_s
        self._writer = asyncio.Lock()
        self.closed = False

    async def send_text(self, data: str) -> None:
        async with asyncio.timeout(self.timeout_s):
            async with self._writer:
                if self.closed:
                    raise ConnectionError("Channel is closed.")
                await self.websocket.send_text(data)

    async def send_json(self, data: dict[str, Any]) -> None:
        await self.send_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False))

    async def close(self, code: int = 1000) -> None:
        async with asyncio.timeout(self.timeout_s):
            async with self._writer:
                if not self.closed:
                    self.closed = True
                    await self.websocket.close(code=code)
