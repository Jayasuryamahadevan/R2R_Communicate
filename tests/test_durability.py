"""Conformance #5 (FASP_PROTOCOL.md ss15): survive restart without skipping
an accepted message or replaying a completed effect.

Complements the narrower restart checks already in test_core.py (peer
pairing) and test_task_lifecycle.py (a crashed-mid-task lease) with one
end-to-end walk: propose, complete, reopen a fresh FaspHarness over the
exact same state_dir, then verify every durable surface -- the task
result, the idempotency guard, and the transport-level replay cache --
all still hold, and a resubmission afterward does not re-invoke the
adapter.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspHarness


class _CountingAdapter(DefaultSafeAdapter):
    def __init__(self) -> None:
        self.calls = 0

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return super().handle(intent)


class DurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_full_lifecycle_survives_a_restart(self) -> None:
        alice = FaspHarness(self.root / "alice", "alice", "http://alice:8766")
        adapter = _CountingAdapter()
        bob = FaspHarness(self.root / "bob", "bob", "http://bob:8766", adapter=adapter)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"])

        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "durable-1", "idempotency_key": "durable-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        duplicate, first_response = bob.accept(envelope)
        self.assertFalse(duplicate)
        self.assertEqual(first_response["status"], "completed")
        self.assertEqual(adapter.calls, 1)

        # Simulate a process restart: a brand new FaspHarness object over
        # the exact same state_dir, with no in-memory state carried over.
        reopened_adapter = _CountingAdapter()
        reopened_bob = FaspHarness(Path(bob.state.directory), "bob", "http://bob:8766", adapter=reopened_adapter)

        # 1. The task's terminal result is unchanged.
        task = reopened_bob.tasks.get("durable-1")
        self.assertEqual(task["state"], "COMPLETED")
        self.assertEqual(task["result"], first_response)

        # 2. Replaying the identical signed envelope does not skip past the
        #    transport-level replay cache or re-invoke the adapter.
        duplicate, replayed_response = reopened_bob.accept(envelope)
        self.assertTrue(duplicate)
        self.assertEqual(replayed_response, first_response)
        self.assertEqual(reopened_adapter.calls, 0)

        # 3. A freshly signed envelope reusing the same idempotency_key
        #    also does not repeat the effect (application-level guarantee,
        #    independent of the transport-level replay cache).
        resubmitted = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "durable-1", "idempotency_key": "durable-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        duplicate, resubmitted_response = reopened_bob.accept(resubmitted)
        self.assertFalse(duplicate)  # new message_id -> not a transport-level duplicate
        self.assertEqual(resubmitted_response, first_response)
        self.assertEqual(reopened_adapter.calls, 0)

        # 4. The audit chain recorded across both the original process and
        #    the reopened one still verifies as one unbroken chain.
        ok, bad_seq = reopened_bob.audit.verify()
        self.assertTrue(ok)
        self.assertIsNone(bad_seq)


if __name__ == "__main__":
    unittest.main()
