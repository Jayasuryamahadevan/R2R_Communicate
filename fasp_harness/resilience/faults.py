"""A deterministic, adversarial network you can put a system inside.

Everything is driven by virtual time and one seeded PRNG. There are no
sleeps and no threads, so a scenario that takes four simulated hours runs
in milliseconds and produces byte-identical results on every machine. That
determinism is the whole value: a resilience bug found here comes with a
seed that reproduces it exactly, which is the difference between a test and
a rumour.

The fault model is the one that actually bites industrial wireless:

  loss          a frame simply never arrives (fading, interference)
  duplication   a retransmit at a lower layer arrives twice
  reordering    two frames take different paths or different retry counts
  corruption    a frame arrives damaged -- the receiver must detect it,
                which for FASP means the signature check must fail
  latency       a range, not a constant; jitter is what breaks timeouts
  partition     no frames at all, in one or both directions, for a while

Asymmetric partitions are supported deliberately, because they are both
common (a directional antenna, a firewall rule, a full receive buffer) and
much nastier than symmetric ones: A believes it is talking to B while B
hears nothing, so A's timeouts never fire.
"""

from __future__ import annotations

import heapq
import itertools
import random
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LinkProfile:
    """The behaviour of one directed link."""

    loss_ratio: float = 0.0
    duplicate_ratio: float = 0.0
    reorder_ratio: float = 0.0
    corrupt_ratio: float = 0.0
    latency_ms: tuple[float, float] = (1.0, 5.0)
    partitioned: bool = False
    max_in_flight: int = 0
    """0 means unbounded. A positive value models a finite queue: once that
    many frames are in flight, further sends are dropped -- the tail-drop
    behaviour a saturated radio or a full socket buffer actually shows."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def perfect(cls) -> LinkProfile:
        return cls(latency_ms=(0.0, 0.0))

    @classmethod
    def industrial_wifi(cls) -> LinkProfile:
        """A plausible aisle-of-steel-racking profile: lossy, jittery, and
        occasionally duplicating, but not partitioned."""
        return cls(loss_ratio=0.08, duplicate_ratio=0.02, reorder_ratio=0.05, latency_ms=(8.0, 120.0))

    @classmethod
    def lte_backhaul(cls) -> LinkProfile:
        return cls(loss_ratio=0.01, latency_ms=(30.0, 250.0))


@dataclass
class NetworkReport:
    """What the network did to the traffic that crossed it."""

    sent: int = 0
    delivered: int = 0
    dropped_loss: int = 0
    dropped_partition: int = 0
    dropped_queue_full: int = 0
    duplicated: int = 0
    reordered: int = 0
    corrupted: int = 0
    per_link: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def delivery_ratio(self) -> float:
        return self.delivered / self.sent if self.sent else 0.0


@dataclass(order=True)
class _ScheduledFrame:
    due_ms: float
    sequence: int
    source: str = field(compare=False)
    destination: str = field(compare=False)
    payload: Any = field(compare=False)
    corrupted: bool = field(compare=False, default=False)


class SimulatedNetwork:
    """Virtual-time message transport with per-link fault injection."""

    def __init__(self, seed: int = 0) -> None:
        self.random = random.Random(seed)
        self.seed = seed
        self.now_ms: float = 0.0
        self.report = NetworkReport()
        self._links: dict[tuple[str, str], LinkProfile] = {}
        self._default = LinkProfile.perfect()
        self._queue: list[_ScheduledFrame] = []
        self._counter = itertools.count()
        self._in_flight: dict[tuple[str, str], int] = {}
        self._handlers: dict[str, Callable[[str, Any, bool], None]] = {}

    # -- topology -------------------------------------------------------
    def set_default(self, profile: LinkProfile) -> None:
        self._default = profile

    def link(self, source: str, destination: str, profile: LinkProfile, *, bidirectional: bool = True) -> None:
        self._links[(source, destination)] = profile
        if bidirectional:
            self._links[(destination, source)] = profile

    def profile_for(self, source: str, destination: str) -> LinkProfile:
        return self._links.get((source, destination), self._default)

    def partition(self, group_a: Iterable[str], group_b: Iterable[str], *, symmetric: bool = True) -> None:
        """Cut every link between the two groups."""
        left, right = list(group_a), list(group_b)
        for source in left:
            for destination in right:
                self._cut(source, destination)
                if symmetric:
                    self._cut(destination, source)

    def _cut(self, source: str, destination: str) -> None:
        profile = self._links.get((source, destination))
        cut = LinkProfile(**{**asdict(profile), "partitioned": True}) if profile else LinkProfile(**{**asdict(self._default), "partitioned": True})
        self._links[(source, destination)] = cut

    def heal(self) -> None:
        """Restore every partitioned link. Traffic dropped while partitioned
        stays dropped -- healing a partition does not un-drop frames, and a
        simulator that pretended otherwise would hide exactly the bug this
        exists to find."""
        for key, profile in list(self._links.items()):
            if profile.partitioned:
                self._links[key] = LinkProfile(**{**asdict(profile), "partitioned": False})

    # -- traffic ----------------------------------------------------------
    def on_receive(self, node: str, handler: Callable[[str, Any, bool], None]) -> None:
        """Register `handler(source, payload, corrupted)` for `node`."""
        self._handlers[node] = handler

    def send(self, source: str, destination: str, payload: Any) -> None:
        """Offer one frame to the network. It may not arrive."""
        self.report.sent += 1
        key = f"{source}->{destination}"
        self.report.per_link[key] = self.report.per_link.get(key, 0) + 1
        profile = self.profile_for(source, destination)
        if profile.partitioned:
            self.report.dropped_partition += 1
            return
        if profile.max_in_flight and self._in_flight.get((source, destination), 0) >= profile.max_in_flight:
            self.report.dropped_queue_full += 1
            return
        if self.random.random() < profile.loss_ratio:
            self.report.dropped_loss += 1
            return

        copies = 1
        if self.random.random() < profile.duplicate_ratio:
            copies = 2
            self.report.duplicated += 1
        for copy_index in range(copies):
            low, high = profile.latency_ms
            delay = self.random.uniform(low, high) if high > low else low
            if copy_index == 0 and self.random.random() < profile.reorder_ratio:
                # Reordering modelled as an extra delay of up to one more
                # latency window, so a later frame can genuinely overtake.
                delay += self.random.uniform(low, max(high, low + 1.0))
                self.report.reordered += 1
            corrupted = self.random.random() < profile.corrupt_ratio
            if corrupted:
                self.report.corrupted += 1
            self._in_flight[(source, destination)] = self._in_flight.get((source, destination), 0) + 1
            heapq.heappush(self._queue, _ScheduledFrame(self.now_ms + delay, next(self._counter), source, destination, payload, corrupted))

    # -- time -------------------------------------------------------------
    def advance(self, duration_ms: float) -> int:
        """Run virtual time forward, delivering everything that comes due."""
        return self.advance_to(self.now_ms + duration_ms)

    def advance_to(self, target_ms: float) -> int:
        delivered = 0
        while self._queue and self._queue[0].due_ms <= target_ms:
            frame = heapq.heappop(self._queue)
            self.now_ms = max(self.now_ms, frame.due_ms)
            self._in_flight[(frame.source, frame.destination)] = max(0, self._in_flight.get((frame.source, frame.destination), 1) - 1)
            handler = self._handlers.get(frame.destination)
            if handler is None:
                continue
            self.report.delivered += 1
            delivered += 1
            handler(frame.source, frame.payload, frame.corrupted)
        self.now_ms = max(self.now_ms, target_ms)
        return delivered

    def run(
        self,
        *,
        duration_ms: float,
        tick_ms: float = 50.0,
        on_tick: Callable[[float], None] | None = None,
        until: Callable[[], bool] | None = None,
    ) -> float:
        """Advance virtual time in `tick_ms` steps for up to `duration_ms`.

        `on_tick` is where the system under test does its periodic work --
        drain an outbox, run anti-entropy, expire a lease -- so a scenario
        can model "the link was down for ten minutes and the retry loop kept
        running the whole time". `until` ends the run early once the
        scenario's own success condition holds.

        Note what this deliberately does *not* do: stop as soon as the
        network queue empties. During a partition every send is dropped
        immediately, so an empty queue is exactly what a broken link looks
        like -- ending there would cut the scenario short at the most
        interesting moment.
        """
        deadline = self.now_ms + duration_ms
        while self.now_ms < deadline:
            if on_tick is not None:
                on_tick(self.now_ms)
            if until is not None and until():
                break
            self.advance(min(tick_ms, deadline - self.now_ms))
        if on_tick is not None:
            on_tick(self.now_ms)
        return self.now_ms

    def drain(self, *, max_ms: float = 60_000.0, tick_ms: float = 5.0, on_tick: Callable[[float], None] | None = None) -> float:
        """Advance until nothing is left in flight (or `max_ms` elapses)."""
        return self.run(duration_ms=max_ms, tick_ms=tick_ms, on_tick=on_tick, until=lambda: not self._queue)

    @property
    def in_flight(self) -> int:
        return len(self._queue)
