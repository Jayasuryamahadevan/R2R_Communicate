"""Bounded process-local deduplication for explicitly lossy observations.

Never used for work, permissions, safety or stream control. Unexpired entries
are not evicted to make room: saturation rejects new messages. A receiver
instance ID binds every message to this process, preventing restart replay.
"""

from __future__ import annotations

import copy
import heapq
import threading
import time
from collections.abc import Callable
from typing import Any

from .errors import FaspError

VOLATILE_FEATURE = "fasp.volatile.v1"
VOLATILE_KINDS = frozenset({"heartbeat", "stream.packet"})
MAX_VOLATILE_LIFETIME_S = 5


class VolatileInbox:
    def __init__(self, capacity: int = 4096) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError("Volatile inbox capacity must be a positive integer.")
        self.capacity = capacity
        self._entries: dict[str, tuple[bytes, dict[str, Any]]] = {}
        self._expiry: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def accept(self, message_id: str, digest: bytes, expires_at: float, handle: Callable[[], dict[str, Any]]) -> tuple[bool, dict[str, Any]]:
        with self._lock:
            current = time.time()
            while self._expiry and self._expiry[0][0] <= current:
                _, expired_id = heapq.heappop(self._expiry)
                self._entries.pop(expired_id, None)
            if expires_at <= current:
                raise FaspError("auth.envelope_expired", "Volatile message expired before admission.")
            existing = self._entries.get(message_id)
            if existing is not None:
                if existing[0] != digest:
                    raise FaspError("auth.replay_conflict", "Message ID is bound to different signed content.")
                return True, copy.deepcopy(existing[1])
            if len(self._entries) >= self.capacity:
                raise FaspError("resource.exhausted", "Volatile replay window is full; retry after expiry.")
            response = handle()
            self._entries[message_id] = (digest, copy.deepcopy(response))
            heapq.heappush(self._expiry, (expires_at, message_id))
            return False, response

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._expiry.clear()
