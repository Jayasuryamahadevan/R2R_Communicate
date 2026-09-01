"""Proving the offline story instead of asserting it.

"Resilient to network loss" is the easiest claim in robotics to make and
the hardest to substantiate, because the interesting failures -- a healed
partition delivering a six-minute-old order, two nodes reconverging on
different state, a retry storm taking down the link that just came back --
do not occur on a developer's desk.

This package makes them occur on demand, deterministically:

- `faults`  a seeded, virtual-time network simulator with per-link loss,
            duplication, reordering, corruption, latency, and hard
            partitions. Same seed, same interleaving, every run -- so a
            resilience failure is a reproducible test, not an anecdote.
- `mesh`    store-carry-forward relaying between FASP nodes with no
            end-to-end path, bounded by hop count and TTL, deduplicated by
            the same `message_id` the protocol already replay-guards on.
"""

from __future__ import annotations

from .faults import LinkProfile, NetworkReport, SimulatedNetwork
from .mesh import MeshEnvelope, MeshNode, run_partition_scenario

__all__ = ["LinkProfile", "MeshEnvelope", "MeshNode", "NetworkReport", "SimulatedNetwork", "run_partition_scenario"]
