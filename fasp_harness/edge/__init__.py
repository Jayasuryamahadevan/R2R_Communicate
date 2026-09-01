"""Running this thing on a factory floor, not a laptop.

Industrial edge deployment has three requirements that a single-process
reference harness does not: something must still coordinate when the node
running the coordinator dies; two nodes must never both believe they are
the coordinator; and work must not be lost when the network to the rest of
the plant is simply gone for an hour.

- `lease`   leader election with fencing tokens. Solves the second problem
            properly rather than hopefully -- a superseded leader's actions
            are *rejected*, not merely unlikely.
- `outbox`  durable store-and-forward with capped backoff and dead
            lettering. Solves the third: a partition becomes latency.
- `health`  liveness/readiness/startup probes and graceful drain, so an
            orchestrator can tell "starting" from "broken" from "standby".
"""

from __future__ import annotations

from .health import HealthRegistry, HealthState
from .lease import FencedOperation, LeaderLease, LeaseLost
from .outbox import Outbox, OutboxMessage

__all__ = ["FencedOperation", "HealthRegistry", "HealthState", "LeaderLease", "LeaseLost", "Outbox", "OutboxMessage"]
