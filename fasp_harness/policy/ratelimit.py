"""Token-bucket rate limiting, keyed by IP address or peer_id (FASP_PROTOCOL.md ss10).

Deliberately in-memory, not persisted to SQLite: a rate limiter's state
resetting on restart is normal and expected (nobody wants "you're still
rate-limited from before the crash"), and writing every single token-bucket
decrement to disk would add durability overhead to the single hottest code
path in the harness for a value nothing downstream needs to survive a
restart.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    def __init__(self, rate_per_second: float, burst: int) -> None:
        if rate_per_second <= 0 or burst <= 0:
            raise ValueError("rate_per_second and burst must be positive.")
        self.rate_per_second = rate_per_second
        self.burst = burst
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Consume one token for `key`, returning whether it was available."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.burst), last_refill=now)
                self._buckets[key] = bucket
            else:
                elapsed = now - bucket.last_refill
                bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * self.rate_per_second)
                bucket.last_refill = now
            if bucket.tokens < 1:
                return False
            bucket.tokens -= 1
            return True
