"""Industrial edge: leader election with fencing, store-and-forward, probes."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.edge.health import HealthRegistry, HealthState
from fasp_harness.edge.lease import LeaderLease, LeaseLost
from fasp_harness.edge.outbox import Outbox
from fasp_harness.protocol.errors import FaspError
from fasp_harness.storage.db import Database


class LeaderLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "fasp.db")
        # Virtual time: a lease test that waits for a real TTL to elapse is
        # a slow test that still cannot assert the interesting moment.
        self.now_ms = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def lease(self, node_id: str, ttl_s: float = 10.0, **kwargs) -> LeaderLease:
        return LeaderLease(self.db, node_id=node_id, ttl_s=ttl_s, clock=lambda: self.now_ms, **kwargs)

    def test_only_one_node_holds_the_lease_at_a_time(self) -> None:
        first = self.lease("node-a")
        second = self.lease("node-b")
        self.assertIsNotNone(first.try_acquire(now_ms=0))
        self.assertIsNone(second.try_acquire(now_ms=1_000))
        self.assertTrue(first.is_leader)
        self.assertFalse(second.is_leader)

    def test_renewal_keeps_the_same_fence(self) -> None:
        """A fence identifies a leadership *term*, not a heartbeat: bumping
        it on every renewal would invalidate the holder's own operations."""
        lease = self.lease("node-a")
        first = lease.try_acquire(now_ms=0)
        renewed = lease.try_acquire(now_ms=3_000)
        self.assertEqual(first.fence, renewed.fence)

    def test_takeover_after_expiry_advances_the_fence(self) -> None:
        first = self.lease("node-a", ttl_s=1.0)
        second = self.lease("node-b", ttl_s=1.0)
        held = first.try_acquire(now_ms=0)
        taken = second.try_acquire(now_ms=5_000)
        self.assertIsNotNone(taken)
        self.assertGreater(taken.fence, held.fence)

    def test_a_superseded_leader_is_refused_at_the_moment_of_effect(self) -> None:
        """The whole point. A partitioned old leader still believes it is the
        leader; the guard is what stops its dispatch from landing."""
        first = self.lease("node-a", ttl_s=1.0)
        second = self.lease("node-b", ttl_s=1.0)
        stale = first.try_acquire(now_ms=0)
        second.try_acquire(now_ms=5_000)
        with self.assertRaises(LeaseLost) as raised:
            first.guard(stale)
        self.assertIn("superseded", raised.exception.detail)

    def test_release_fails_over_immediately_and_burns_the_term(self) -> None:
        first = self.lease("node-a", ttl_s=100.0)
        held = first.try_acquire(now_ms=0)
        self.assertTrue(first.release())
        second = self.lease("node-b", ttl_s=100.0)
        taken = second.try_acquire(now_ms=10)
        self.assertIsNotNone(taken)
        self.assertGreater(taken.fence, held.fence)

    def test_a_non_holder_cannot_release_someone_elses_lease(self) -> None:
        self.lease("node-a", ttl_s=100.0).try_acquire(now_ms=0)
        self.assertFalse(self.lease("node-b").release())

    def test_held_raises_rather_than_returning_a_lie(self) -> None:
        lease = self.lease("node-a")
        with self.assertRaises(LeaseLost):
            lease.held()
        lease.try_acquire(now_ms=0)
        self.assertEqual(lease.held().holder, "node-a")

    def test_callbacks_fire_on_acquisition_and_loss(self) -> None:
        acquired: list[int] = []
        lost: list[str] = []
        first = self.lease("node-a", ttl_s=1.0, on_acquire=lambda operation: acquired.append(operation.fence), on_lose=lost.append)
        first.try_acquire(now_ms=0)
        self.assertEqual(acquired, [1])
        self.lease("node-b", ttl_s=1.0).try_acquire(now_ms=5_000)
        first.try_acquire(now_ms=5_100)
        self.assertEqual(len(lost), 1)

    def test_observe_works_from_a_node_that_is_not_campaigning(self) -> None:
        self.lease("node-a", ttl_s=100.0).try_acquire(now_ms=0)
        watcher = self.lease("observer")
        seen = watcher.observe()
        self.assertEqual(seen["holder"], "node-a")
        self.assertFalse(seen["self_is_leader"])
        self.assertTrue(seen["healthy"])

    def test_describe_states_the_limits_of_this_mechanism(self) -> None:
        described = self.lease("node-a").describe()
        self.assertIn("fencing token", described["mechanism"])
        self.assertIn("not one", described["scope"])


class OutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "fasp.db")
        # Deterministic backoff: full jitter is right in production and
        # useless in a test that needs to assert a specific delay.
        self.now_ms = 0
        self.outbox = Outbox(self.db, base_backoff_s=1.0, max_attempts=3, jitter=lambda: 1.0, clock=lambda: self.now_ms)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def envelope(self, message_id: str, kind: str = "intent.propose") -> dict:
        return {"message_id": message_id, "kind": kind, "payload": {}}

    def test_enqueue_is_idempotent_on_message_id(self) -> None:
        first = self.outbox.enqueue("peer-1", self.envelope("m1"))
        second = self.outbox.enqueue("peer-1", self.envelope("m1"))
        self.assertEqual(first.row_id, second.row_id)
        self.assertEqual(self.outbox.depth()["pending"], 1)

    def test_ordering_is_preserved_per_destination_and_independent_across_them(self) -> None:
        """A cancel must not overtake the order it cancels; a dead peer must
        not stall a healthy one."""
        for index in range(3):
            self.outbox.enqueue("peer-1", self.envelope(f"a{index}"))
            self.outbox.enqueue("peer-2", self.envelope(f"b{index}"))
        claimed = self.outbox.claim_ready(now_ms=0)
        self.assertEqual(sorted(message.message_id for message in claimed), ["a0", "b0"])

    def test_a_failure_backs_off_exponentially_then_dead_letters(self) -> None:
        self.outbox.enqueue("peer-1", self.envelope("m1"))
        first = self.outbox.mark_failed(self.outbox.claim_ready(now_ms=0)[0].row_id, "connection refused", now_ms=0)
        self.assertEqual(first["retry_in_s"], 1.0)

        # Nothing is due until the backoff elapses.
        self.assertEqual(self.outbox.claim_ready(now_ms=500), [])
        second = self.outbox.mark_failed(self.outbox.claim_ready(now_ms=1_000)[0].row_id, "still refused", now_ms=1_000)
        self.assertEqual(second["retry_in_s"], 2.0)

        third = self.outbox.mark_failed(self.outbox.claim_ready(now_ms=4_000)[0].row_id, "gave up", now_ms=4_000)
        self.assertEqual(third["state"], "dead")
        self.assertEqual(len(self.outbox.dead_letters()), 1)

    def test_dead_letters_can_be_requeued_after_the_cause_is_fixed(self) -> None:
        self.outbox.enqueue("peer-1", self.envelope("m1"))
        for attempt in range(3):
            self.outbox.mark_failed(self.outbox.claim_ready(now_ms=attempt * 10_000)[0].row_id, "down", now_ms=attempt * 10_000)
        self.assertEqual(self.outbox.requeue_dead(), 1)
        self.assertEqual(self.outbox.depth()["pending"], 1)

    def test_flush_delivers_and_a_raising_sender_becomes_a_retry(self) -> None:
        self.outbox.enqueue("peer-1", self.envelope("m1"))
        self.outbox.enqueue("peer-2", self.envelope("m2"))

        def send(message):
            if message.destination == "peer-2":
                raise ConnectionError("no route")
            return True

        counts = self.outbox.flush(send, now_ms=0)
        self.assertEqual(counts["sent"], 1)
        self.assertEqual(counts["retry"], 1)
        self.assertEqual(self.outbox.depth()["sent"], 1)

    def test_a_message_that_expires_before_delivery_is_dropped_not_delivered_late(self) -> None:
        self.outbox.enqueue("peer-1", self.envelope("m1"), expires_in_s=0.001)
        self.assertEqual(self.outbox.claim_ready(now_ms=10_000), [])
        self.assertEqual(self.outbox.depth()["dead"], 1)

    def test_capacity_is_bounded_rather_than_filling_the_disk(self) -> None:
        outbox = Outbox(self.db, capacity=3, clock=lambda: self.now_ms)
        for index in range(3):
            outbox.enqueue("peer-1", self.envelope(f"m{index}"))
        with self.assertRaises(FaspError) as raised:
            outbox.enqueue("peer-1", self.envelope("overflow"))
        self.assertEqual(raised.exception.code, "resource.exhausted")

    def test_an_envelope_without_a_message_id_is_refused(self) -> None:
        with self.assertRaises(FaspError):
            self.outbox.enqueue("peer-1", {"kind": "intent.propose"})

    def test_delivered_messages_are_purged_on_a_retention_schedule(self) -> None:
        self.outbox.enqueue("peer-1", self.envelope("m1"))
        self.outbox.flush(lambda message: True, now_ms=0)
        self.assertEqual(self.outbox.purge_sent(older_than_s=-1.0), 1)
        self.assertEqual(self.outbox.depth()["sent"], 0)


class HealthTests(unittest.TestCase):
    def test_a_standby_is_alive_but_not_ready(self) -> None:
        """The case a single boolean cannot express: healthy, must not be
        restarted, must not be given work."""
        health = HealthRegistry(node_id="standby")
        health.register("database", lambda: (True, "ok"), critical=True)
        health.register("leadership", lambda: (False, "standby"), critical=False)
        health.mark_started()
        live, _ = health.live()
        ready, body = health.ready()
        self.assertTrue(live)
        self.assertFalse(ready)
        self.assertEqual(body["state"], HealthState.DEGRADED.value)

    def test_startup_is_distinct_from_broken(self) -> None:
        health = HealthRegistry()
        health.register("database", lambda: (True, "ok"), critical=True)
        ready, body = health.ready()
        self.assertFalse(ready)
        self.assertEqual(body["state"], HealthState.STARTING.value)
        self.assertTrue(health.live()[0])

    def test_a_critical_check_failure_fails_liveness(self) -> None:
        health = HealthRegistry()
        health.register("database", lambda: (False, "disk gone"), critical=True)
        health.mark_started()
        self.assertFalse(health.live()[0])

    def test_draining_stops_routing_without_failing_liveness(self) -> None:
        health = HealthRegistry()
        health.register("database", lambda: (True, "ok"), critical=True)
        health.mark_started()
        health.begin_drain()
        self.assertTrue(health.live()[0])
        ready, body = health.ready()
        self.assertFalse(ready)
        self.assertEqual(body["state"], HealthState.DRAINING.value)

    def test_a_probe_that_raises_reports_failed_instead_of_crashing(self) -> None:
        health = HealthRegistry()

        def explode() -> tuple[bool, str]:
            raise RuntimeError("nope")

        health.register("boom", explode)
        health.mark_started()
        ready, body = health.ready()
        self.assertFalse(ready)
        self.assertIn("check raised", body["checks"][0]["detail"])

    def test_re_registering_a_check_replaces_it(self) -> None:
        health = HealthRegistry()
        health.register("x", lambda: (False, "old"))
        health.register("x", lambda: (True, "new"))
        health.mark_started()
        self.assertEqual(len(health.evaluate()), 1)
        self.assertTrue(health.ready()[0])


if __name__ == "__main__":
    unittest.main()
