"""Store-carry-forward relaying for nodes with no end-to-end path.

An AMR parked at the far end of a warehouse can often reach a neighbour it
cannot route through: it is on the same radio, it is simply not on the same
subnet as the coordinator, or the uplink is down. Delay-tolerant networking
has a well-worn answer -- carry the message, forward it when a contact
opens -- and it maps cleanly onto FASP because the properties it needs are
already in the protocol:

- messages are self-contained, signed envelopes, so a relay does not need
  to be trusted to carry one and cannot alter it undetected;
- `message_id` already keys a durable replay-dedup gate at the receiver,
  so multi-path flooding cannot cause a duplicated effect;
- `expires_at` already bounds how long a message is worth carrying.

A relay here is exactly that: a carrier. It never opens, interprets, or
acts on an envelope addressed to someone else -- `MeshNode.accept()` only
inspects routing metadata, and the payload is opaque bytes to it. The
security property that makes the whole idea acceptable is that relaying
requires no trust: a malicious relay can drop or delay, which the network
could do anyway, but it cannot forge, read past the envelope's own
authenticated framing, or replay to effect.

Bounded by three counters, because flooding without bounds is a denial of
service you build yourself: hop limit, TTL, and per-node carry capacity.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .faults import LinkProfile, SimulatedNetwork

DEFAULT_HOP_LIMIT = 6
DEFAULT_CARRY_CAPACITY = 512


@dataclass
class MeshEnvelope:
    """One carried message, plus the routing metadata a relay may read."""

    message_id: str
    origin: str
    destination: str
    payload: Any
    hops: int = 0
    hop_limit: int = DEFAULT_HOP_LIMIT
    expires_at_ms: float = float("inf")
    path: tuple[str, ...] = ()

    def forwardable(self, now_ms: float) -> bool:
        return self.hops < self.hop_limit and now_ms < self.expires_at_ms

    def relayed_via(self, node: str) -> MeshEnvelope:
        return MeshEnvelope(
            message_id=self.message_id,
            origin=self.origin,
            destination=self.destination,
            payload=self.payload,
            hops=self.hops + 1,
            hop_limit=self.hop_limit,
            expires_at_ms=self.expires_at_ms,
            path=(*self.path, node),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"message_id": self.message_id, "origin": self.origin, "destination": self.destination, "hops": self.hops, "path": list(self.path)}


@dataclass
class MeshStats:
    originated: int = 0
    delivered: int = 0
    relayed: int = 0
    duplicates_suppressed: int = 0
    expired: int = 0
    hop_limited: int = 0
    dropped_capacity: int = 0
    corrupted_rejected: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "originated": self.originated,
            "delivered": self.delivered,
            "relayed": self.relayed,
            "duplicates_suppressed": self.duplicates_suppressed,
            "expired": self.expired,
            "hop_limited": self.hop_limited,
            "dropped_capacity": self.dropped_capacity,
            "corrupted_rejected": self.corrupted_rejected,
        }


class MeshNode:
    """A FASP node that also carries other nodes' messages toward them."""

    def __init__(
        self,
        node_id: str,
        network: SimulatedNetwork,
        *,
        neighbours: Iterable[str] = (),
        carry_capacity: int = DEFAULT_CARRY_CAPACITY,
        on_deliver: Callable[[MeshEnvelope], None] | None = None,
        relay: bool = True,
    ) -> None:
        self.node_id = node_id
        self.network = network
        self.neighbours: set[str] = set(neighbours)
        self.carry_capacity = carry_capacity
        self.on_deliver = on_deliver
        self.relay = relay
        self.stats = MeshStats()
        self.received: list[MeshEnvelope] = []
        self._seen: set[str] = set()
        self._carrying: dict[str, MeshEnvelope] = {}
        self._forwarded: dict[str, set[str]] = {}
        network.on_receive(node_id, self._on_frame)

    # -- membership ------------------------------------------------------
    def add_neighbour(self, node_id: str) -> None:
        self.neighbours.add(node_id)

    # -- origination -----------------------------------------------------
    def send(self, destination: str, message_id: str, payload: Any, *, ttl_ms: float = 600_000.0, hop_limit: int = DEFAULT_HOP_LIMIT) -> MeshEnvelope:
        envelope = MeshEnvelope(
            message_id=message_id,
            origin=self.node_id,
            destination=destination,
            payload=payload,
            hop_limit=hop_limit,
            expires_at_ms=self.network.now_ms + ttl_ms,
            path=(self.node_id,),
        )
        self.stats.originated += 1
        self._seen.add(message_id)
        self._carry(envelope)
        self._offer(envelope)
        return envelope

    # -- reception --------------------------------------------------------
    def _on_frame(self, source: str, payload: Any, corrupted: bool) -> None:
        del source
        if corrupted:
            # A corrupted frame is discarded here rather than "repaired".
            # In a real deployment the envelope signature is what detects
            # this; the mesh layer's job is only to not propagate it.
            self.stats.corrupted_rejected += 1
            return
        if isinstance(payload, MeshEnvelope):
            self.accept(payload)

    def accept(self, envelope: MeshEnvelope) -> None:
        """Take custody of a message: deliver it, carry it, or drop it."""
        now_ms = self.network.now_ms
        if envelope.message_id in self._seen:
            self.stats.duplicates_suppressed += 1
            # Still worth re-offering onward if we are carrying it and a
            # new contact has opened since; that is what makes a healed
            # partition drain instead of sitting idle.
            carried = self._carrying.get(envelope.message_id)
            if carried is not None:
                self._offer(carried)
            return
        self._seen.add(envelope.message_id)

        if envelope.destination == self.node_id:
            self.stats.delivered += 1
            self.received.append(envelope)
            if self.on_deliver is not None:
                self.on_deliver(envelope)
            return
        if not self.relay:
            return
        if now_ms >= envelope.expires_at_ms:
            self.stats.expired += 1
            return
        if envelope.hops >= envelope.hop_limit:
            self.stats.hop_limited += 1
            return
        relayed = envelope.relayed_via(self.node_id)
        self.stats.relayed += 1
        self._carry(relayed)
        self._offer(relayed)

    def _carry(self, envelope: MeshEnvelope) -> None:
        if len(self._carrying) >= self.carry_capacity:
            # Drop the message closest to expiry: it is the one least likely
            # to still be useful, and dropping the newest instead would
            # starve fresh traffic during congestion.
            oldest = min(self._carrying.values(), key=lambda item: item.expires_at_ms)
            del self._carrying[oldest.message_id]
            self.stats.dropped_capacity += 1
        self._carrying[envelope.message_id] = envelope

    # -- forwarding --------------------------------------------------------
    def _offer(self, envelope: MeshEnvelope) -> None:
        """Offer to every neighbour not already on the path.

        Path-based suppression rather than a routing table: a mesh whose
        topology changes every time a vehicle turns a corner has no stable
        routes to keep, and the envelope already records where it has been.
        """
        if not envelope.forwardable(self.network.now_ms):
            # Counted here rather than on the receiving side: this is where
            # the message actually stops. A node whose relay would exceed
            # the hop limit never offers it, so no downstream node ever sees
            # an over-limit envelope to count.
            if envelope.hops >= envelope.hop_limit:
                self.stats.hop_limited += 1
            else:
                self.stats.expired += 1
            return
        already = self._forwarded.setdefault(envelope.message_id, set())
        for neighbour in sorted(self.neighbours):
            if neighbour in envelope.path or neighbour in already:
                continue
            already.add(neighbour)
            self.network.send(self.node_id, neighbour, envelope)

    def tick(self, now_ms: float) -> None:
        """Periodic anti-entropy: re-offer everything still carried.

        This is what turns a healed partition into a delivery. Contacts are
        not announced, so the only way to discover that a neighbour became
        reachable is to try, periodically, and let the network drop what it
        cannot carry.
        """
        expired = [message_id for message_id, envelope in self._carrying.items() if now_ms >= envelope.expires_at_ms]
        for message_id in expired:
            del self._carrying[message_id]
            self.stats.expired += 1
        for envelope in list(self._carrying.values()):
            self._forwarded.pop(envelope.message_id, None)
            self._offer(envelope)

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "neighbours": sorted(self.neighbours), "carrying": len(self._carrying), "stats": self.stats.to_dict()}


@dataclass
class ScenarioReport:
    """The verdict of one partition/loss scenario."""

    seed: int
    sent: int
    delivered: int
    delivered_during_partition: int
    duplicate_deliveries: int
    virtual_ms: float
    network: dict[str, Any] = field(default_factory=dict)
    nodes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.delivered == self.sent and self.duplicate_deliveries == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "sent": self.sent,
            "delivered": self.delivered,
            "delivered_during_partition": self.delivered_during_partition,
            "duplicate_deliveries": self.duplicate_deliveries,
            "complete": self.complete,
            "virtual_ms": self.virtual_ms,
            "network": self.network,
            "nodes": self.nodes,
        }


def run_partition_scenario(
    *,
    seed: int = 1,
    node_ids: tuple[str, ...] = ("edge-a", "relay-1", "relay-2", "coordinator"),
    profile: LinkProfile | None = None,
    messages: int = 20,
    partition_after_ms: float = 500.0,
    partition_duration_ms: float = 60_000.0,
    settle_ms: float = 60_000.0,
    tick_ms: float = 250.0,
) -> ScenarioReport:
    """Send traffic across a chain, cut it, heal it, and check what arrived.

    The chain topology is the point: with the middle link cut there is no
    end-to-end path at all, so any message that arrives did so because a
    relay carried it across the outage. A delivery ratio of 1.0 with zero
    duplicate deliveries is then a real property of store-carry-forward plus
    `message_id` dedup, not an artefact of the network having been fine.
    """
    network = SimulatedNetwork(seed=seed)
    network.set_default(profile or LinkProfile.industrial_wifi())
    for left, right in zip(node_ids, node_ids[1:], strict=False):
        network.link(left, right, profile or LinkProfile.industrial_wifi())

    delivered_ids: list[str] = []
    nodes: dict[str, MeshNode] = {}
    for index, node_id in enumerate(node_ids):
        neighbours = [neighbour for neighbour in (node_ids[index - 1] if index else None, node_ids[index + 1] if index + 1 < len(node_ids) else None) if neighbour]
        nodes[node_id] = MeshNode(node_id, network, neighbours=neighbours, on_deliver=lambda envelope: delivered_ids.append(envelope.message_id))

    source, destination = node_ids[0], node_ids[-1]
    midpoint = len(node_ids) // 2
    left_group, right_group = node_ids[:midpoint], node_ids[midpoint:]

    def tick(now_ms: float) -> None:
        for node in nodes.values():
            node.tick(now_ms)

    # Partition FIRST, then originate. A scenario that sends while the
    # network is healthy proves nothing about carrying: the traffic simply
    # arrives, and the outage that follows is irrelevant to it.
    network.run(duration_ms=partition_after_ms, tick_ms=tick_ms, on_tick=tick)
    network.partition(left_group, right_group)
    for index in range(messages):
        nodes[source].send(destination, f"msg-{index:04d}", {"index": index}, ttl_ms=partition_duration_ms + settle_ms + 10_000.0)
    network.run(duration_ms=partition_duration_ms, tick_ms=tick_ms, on_tick=tick)
    delivered_during_partition = len(set(delivered_ids))
    network.heal()
    network.run(duration_ms=settle_ms, tick_ms=tick_ms, on_tick=tick, until=lambda: len(set(delivered_ids)) == messages)

    return ScenarioReport(
        seed=seed,
        sent=messages,
        delivered=len(set(delivered_ids)),
        delivered_during_partition=delivered_during_partition,
        duplicate_deliveries=len(delivered_ids) - len(set(delivered_ids)),
        virtual_ms=network.now_ms,
        network=network.report.to_dict(),
        nodes=[node.to_dict() for node in nodes.values()],
    )
