"""Leader election with fencing tokens, over the database already present.

The hard part of hot standby is not electing a leader. It is what happens
to the *old* leader: a node that was the leader, lost the network for
ninety seconds, and has not yet noticed. It still holds its in-memory
"I am the leader" flag, and it is about to dispatch a mission to a vehicle
the new leader has already assigned elsewhere.

Timeouts alone cannot fix this, because the old leader's clock and the
new leader's clock disagree about exactly the interval in question. The
fix is a fencing token: a monotonically increasing integer, bumped on every
change of holder, that must be presented alongside any action that matters.
The database refuses a stale token, so the old leader's dispatch fails at
the point of effect rather than being merely improbable. (Lamport, 1998;
the same construct ZooKeeper exposes as zxid and Chubby as a sequencer.)

`LeaderLease` deliberately uses this harness's existing SQLite database
rather than adding a consensus system. That is an honest trade with a
stated boundary: SQLite gives correct mutual exclusion between processes
on *one* host or on one shared filesystem with working locks, which covers
the common industrial-edge pattern of an active/standby pair on the same
appliance. It is not a replacement for Raft across independent machines,
and `describe()` says so, so a deployment cannot silently assume a
guarantee it does not have.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..protocol.errors import FaspError
from ..storage.db import Database
from ..timestamps import stamp


class LeaseLost(FaspError):
    """This node acted as leader without currently being one."""

    def __init__(self, detail: str) -> None:
        super().__init__("lease.expired", detail)


@dataclass(frozen=True)
class FencedOperation:
    """Proof of leadership at a point in time, passed to guarded work.

    A caller holds one of these for the duration of one operation. It is
    frozen and carries the fence it was minted with, so a long-running
    operation cannot quietly upgrade itself to a newer fence halfway
    through -- it either completes under the leadership it started with, or
    is rejected.
    """

    name: str
    holder: str
    fence: int
    expires_at_ms: int

    def valid_now(self, now_ms: int | None = None) -> bool:
        return (now_ms if now_ms is not None else int(time.time() * 1000)) < self.expires_at_ms


def default_node_id() -> str:
    """Stable within a process, distinct between processes on one host."""
    return f"{socket.gethostname()}:{os.getpid()}"


class LeaderLease:
    """A renewable, fenced, single-holder lease over one named role."""

    def __init__(
        self,
        db: Database,
        name: str = "fleet-coordinator",
        *,
        node_id: str | None = None,
        ttl_s: float = 15.0,
        renew_interval_s: float | None = None,
        on_acquire: Callable[[FencedOperation], None] | None = None,
        on_lose: Callable[[str], None] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if ttl_s <= 0:
            raise ValueError("ttl_s must be positive.")
        self.db = db
        self.name = name
        self.node_id = node_id or default_node_id()
        self.ttl_ms = int(ttl_s * 1000)
        # Renew at a third of the TTL: two consecutive renewals can be lost
        # before the lease actually lapses, which is the standard margin for
        # surviving a transient stall without extending the failover time.
        self.renew_interval_s = renew_interval_s if renew_interval_s is not None else ttl_s / 3.0
        self.on_acquire = on_acquire
        self.on_lose = on_lose
        # One clock for the whole lease. Mixing an injected time for
        # acquisition with the wall clock for validity is an easy mistake
        # and a nasty one: the lease would be taken at one epoch and judged
        # against another, so `try_acquire` would succeed and `is_leader`
        # would immediately disagree with it.
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.Lock()
        self._held: FencedOperation | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def now_ms(self) -> int:
        return int(self._clock())

    # -- election -----------------------------------------------------
    def try_acquire(self, now_ms: int | None = None, metadata: dict[str, Any] | None = None) -> FencedOperation | None:
        """Take or renew the lease. One transaction, no read-then-write gap."""
        now_ms = now_ms if now_ms is not None else self.now_ms()
        expires = now_ms + self.ttl_ms
        acquired: FencedOperation | None = None
        changed = False
        with self.db.write() as conn:
            row = conn.execute("SELECT holder, fence, expires_at_ms, acquired_at FROM leases WHERE name = ?", (self.name,)).fetchone()
            if row is None:
                fence = 1
                conn.execute(
                    "INSERT INTO leases (name, holder, fence, acquired_at, renewed_at, expires_at_ms, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (self.name, self.node_id, fence, stamp(), stamp(), expires, _json(metadata)),
                )
                acquired, changed = FencedOperation(self.name, self.node_id, fence, expires), True
            elif row["holder"] == self.node_id and row["expires_at_ms"] > now_ms:
                # Renewal by the current holder keeps the fence: the fence
                # identifies a *leadership term*, not a heartbeat.
                conn.execute("UPDATE leases SET renewed_at = ?, expires_at_ms = ? WHERE name = ? AND holder = ?", (stamp(), expires, self.name, self.node_id))
                acquired = FencedOperation(self.name, self.node_id, int(row["fence"]), expires)
            elif row["expires_at_ms"] <= now_ms:
                fence = int(row["fence"]) + 1
                conn.execute(
                    "UPDATE leases SET holder = ?, fence = ?, acquired_at = ?, renewed_at = ?, expires_at_ms = ?, metadata_json = ? WHERE name = ?",
                    (self.node_id, fence, stamp(), stamp(), expires, _json(metadata), self.name),
                )
                acquired, changed = FencedOperation(self.name, self.node_id, fence, expires), True
        with self._lock:
            previously = self._held
            self._held = acquired
        if acquired is None and previously is not None and self.on_lose is not None:
            self.on_lose("Lease is held by another node.")
        if changed and acquired is not None and self.on_acquire is not None:
            self.on_acquire(acquired)
        return acquired

    def release(self, now_ms: int | None = None) -> bool:
        """Give the lease up immediately, so a planned shutdown fails over
        in milliseconds instead of after a full TTL. Bumps the fence, so
        the released term can never be resumed."""
        del now_ms
        with self.db.write() as conn:
            row = conn.execute("SELECT holder, fence FROM leases WHERE name = ?", (self.name,)).fetchone()
            if row is None or row["holder"] != self.node_id:
                released = False
            else:
                conn.execute("UPDATE leases SET expires_at_ms = 0, fence = ? WHERE name = ? AND holder = ?", (int(row["fence"]) + 1, self.name, self.node_id))
                released = True
        with self._lock:
            self._held = None
        if released and self.on_lose is not None:
            self.on_lose("Lease released by this node.")
        return released

    # -- guarded execution ---------------------------------------------
    @property
    def is_leader(self) -> bool:
        with self._lock:
            held = self._held
        return held is not None and held.valid_now(self.now_ms())

    def held(self) -> FencedOperation:
        """The current leadership proof, or raise. Call this at the top of
        anything that must only happen on the leader."""
        with self._lock:
            held = self._held
        if held is None:
            raise LeaseLost(f"This node does not hold the {self.name!r} lease.")
        if not held.valid_now(self.now_ms()):
            raise LeaseLost(f"This node's {self.name!r} lease expired at {held.expires_at_ms}.")
        return held

    def guard(self, operation: FencedOperation) -> None:
        """Verify a fence against the database at the moment of effect.

        This is the call that actually prevents split-brain damage: a node
        that lost the lease during a long operation is refused here, because
        the stored fence has moved past the one it is presenting.
        """
        row = self.db.read_one("SELECT holder, fence, expires_at_ms FROM leases WHERE name = ?", (operation.name,))
        if row is None:
            raise LeaseLost(f"Lease {operation.name!r} no longer exists.")
        if int(row["fence"]) > operation.fence:
            raise LeaseLost(f"Fence {operation.fence} is stale; leadership has advanced to {int(row['fence'])}. Refusing to act as a superseded leader.")
        if row["holder"] != operation.holder or int(row["expires_at_ms"]) <= self.now_ms():
            raise LeaseLost(f"Lease {operation.name!r} is no longer held by this node.")

    def observe(self) -> dict[str, Any]:
        """Who holds it, from any node, without taking part in the election."""
        row = self.db.read_one("SELECT * FROM leases WHERE name = ?", (self.name,))
        now_ms = self.now_ms()
        if row is None:
            return {"name": self.name, "holder": None, "fence": 0, "healthy": False, "self_is_leader": False}
        return {
            "name": self.name,
            "holder": row["holder"],
            "fence": int(row["fence"]),
            "acquired_at": row["acquired_at"],
            "renewed_at": row["renewed_at"],
            "expires_in_ms": int(row["expires_at_ms"]) - now_ms,
            "healthy": int(row["expires_at_ms"]) > now_ms,
            "self_is_leader": row["holder"] == self.node_id and int(row["expires_at_ms"]) > now_ms,
        }

    # -- background renewal ---------------------------------------------
    def start(self) -> LeaderLease:
        if self._thread is not None:
            return self
        self._stop.clear()
        self.try_acquire()

        def target() -> None:
            while not self._stop.wait(self.renew_interval_s):
                try:
                    self.try_acquire()
                except Exception:  # noqa: BLE001 - a transient DB error must not end the campaign
                    continue

        self._thread = threading.Thread(target=target, name=f"fasp-lease-{self.name}", daemon=True)
        self._thread.start()
        return self

    def stop(self, *, release: bool = True) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=max(self.renew_interval_s * 2, 1.0))
        if release:
            self.release()

    def describe(self) -> dict[str, Any]:
        return {
            **self.observe(),
            "node_id": self.node_id,
            "ttl_ms": self.ttl_ms,
            "renew_interval_ms": int(self.renew_interval_s * 1000),
            "mechanism": "SQLite transactional compare-and-set with a monotonic fencing token",
            "scope": "Correct for active/standby processes sharing one database file. Cross-machine HA needs a real consensus service; this is not one.",
        }


def _json(value: dict[str, Any] | None) -> str | None:
    if value is None:
        return None
    import json

    return json.dumps(value, sort_keys=True)
