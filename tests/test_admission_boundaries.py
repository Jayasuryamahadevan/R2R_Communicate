"""Resource bounds under contention, identity churn, and restart."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fasp_harness.audit.chain import AuditChain
from fasp_harness.core import FaspError, FaspHarness, now, stamp
from fasp_harness.crypto.identity import Identity
from fasp_harness.policy.ratelimit import TokenBucketLimiter
from fasp_harness.storage.db import Database
from fasp_harness.storage.tasks_repo import TasksRepo


class AdmissionBoundaryTests(unittest.TestCase):
    def test_capacity_is_atomic_across_independent_database_connections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.db"
            databases = [Database(path), Database(path)]
            repositories = [TasksRepo(db, AuditChain(db, "local-test")) for db in databases]
            start = threading.Barrier(16)

            def propose(index: int) -> bool:
                start.wait(timeout=5)
                try:
                    return repositories[index % 2].propose(str(index), str(index), "observe.status.v1", "peer", stamp(), max_active=3)
                except FaspError as error:
                    self.assertEqual(error.code, "resource.exhausted")
                    return False

            try:
                with ThreadPoolExecutor(max_workers=16) as pool:
                    accepted = list(pool.map(propose, range(16)))
                self.assertEqual(sum(accepted), 3)
                self.assertEqual(repositories[0].count_inflight(), 3)
                for db in databases:
                    self.assertTrue(AuditChain(db, "local-test").verify()[0])
            finally:
                for db in databases:
                    db.close()

    def test_existing_result_is_available_when_queue_is_full_and_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alice = FaspHarness(root / "alice", "alice", "http://alice")
            bob = FaspHarness(root / "bob", "bob", "http://bob", max_inflight_tasks=1)
            try:
                hello = bob.hello(alice.id_card())
                bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
                payload = {"idempotency_key": "completed", "capability": "observe.system.status.v1"}
                _, original = bob.accept(alice.make_envelope("intent.propose", bob.identity.system_id, payload))
                bob.tasks.propose("busy", "busy", "observe.system.status.v1", alice.identity.system_id, stamp(), max_active=1)
                for restarted in (False, True):
                    if restarted:
                        bob.close()
                        bob = FaspHarness(root / "bob", "bob", "http://bob", max_inflight_tasks=1)
                    _, result = bob.accept(alice.make_envelope("intent.propose", bob.identity.system_id, payload))
                    self.assertEqual(result, original)
                    with self.assertRaises(FaspError) as error:
                        bob.accept(alice.make_envelope("intent.propose", bob.identity.system_id, {**payload, "idempotency_key": f"new-{restarted}"}))
                    self.assertEqual(error.exception.code, "resource.exhausted")
            finally:
                alice.close()
                bob.close()

    def test_limiter_memory_is_bounded_and_churn_cannot_reset_a_quota(self) -> None:
        limiter = TokenBucketLimiter(1, 2, max_keys=2)
        with patch("fasp_harness.policy.ratelimit.time.monotonic", return_value=0):
            self.assertTrue(limiter.allow("alice"))
            self.assertTrue(limiter.allow("alice"))
            self.assertTrue(limiter.allow("bob"))
            for index in range(100):
                self.assertFalse(limiter.allow(f"churn-{index}"))
            self.assertFalse(limiter.allow("alice"))
            self.assertEqual(len(limiter._buckets), 2)
        with patch("fasp_harness.policy.ratelimit.time.monotonic", return_value=3):
            self.assertTrue(limiter.allow("new"))
            self.assertEqual(len(limiter._buckets), 2)

    def test_capacity_refusal_can_be_retried_with_the_same_signed_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alice = FaspHarness(root / "alice", "alice", "http://alice")
            bob = FaspHarness(root / "bob", "bob", "http://bob", max_inflight_tasks=1)
            try:
                hello = bob.hello(alice.id_card())
                bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
                bob.tasks.propose("busy", "busy", "observe.system.status.v1", alice.identity.system_id, stamp(), max_active=1)
                envelope = alice.make_envelope("intent.propose", bob.identity.system_id, {"idempotency_key": "retry", "capability": "observe.system.status.v1"})
                with self.assertRaises(FaspError):
                    bob.accept(envelope)
                self.assertIsNone(bob.inbox.get_response(envelope["message_id"]))
                self.assertTrue(bob.tasks.cancel_immediately("busy", stamp()))
                duplicate, result = bob.accept(envelope)
                self.assertFalse(duplicate)
                self.assertEqual(result["status"], "completed")
                self.assertEqual(bob.accept(envelope), (True, result))
            finally:
                alice.close()
                bob.close()
    def test_limiter_rejects_invalid_configuration(self) -> None:
        for rate, burst, keys in ((float("nan"), 2, 2), (float("inf"), 2, 2), (1, True, 2), (1, 1, 0)):
            with self.assertRaises(ValueError):
                TokenBucketLimiter(rate, burst, max_keys=keys)

    def test_pending_pairings_are_bounded_and_expire_without_removing_trusted_peers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            members = [FaspHarness(root / str(index), str(index), "http://local") for index in range(4)]
            bob, alice, carol, david = members
            bob.peers.max_pending = 1
            try:
                hello = bob.hello(alice.id_card())
                bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
                bob.hello(carol.id_card())
                with self.assertRaises(FaspError) as error:
                    bob.hello(david.id_card())
                self.assertEqual(error.exception.code, "resource.exhausted")
                bob.hello(alice.id_card())
                self.assertEqual(bob.peers.get(alice.identity.system_id)["state"], "paired")
                with bob.db.write() as connection:
                    connection.execute("UPDATE peers SET seen_at = ? WHERE state = 'pending'", (stamp(now() - timedelta(minutes=16)),))
                bob.hello(david.id_card())
                self.assertIsNone(bob.peers.get(carol.identity.system_id))
                self.assertEqual(len(bob.peers.all()), 2)
            finally:
                for member in members:
                    member.close()

    def test_corrupt_local_identity_is_rejected_instead_of_advertised(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            Identity.load_or_create(path)
            record = json.loads(path.read_text())
            record["system_id"] = "fasp:system:wrong-key"
            path.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                Identity.load_or_create(path)
