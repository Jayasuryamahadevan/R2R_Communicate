"""Conformance #3 (idempotent duplicate handling, no repeated effect) and
#6 (expire a stale lease to a safe terminal state) from FASP_PROTOCOL.md ss15."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness


class _CountingAdapter(DefaultSafeAdapter):
    def __init__(self) -> None:
        self.calls = 0

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return super().handle(intent)


class TaskLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.adapter = _CountingAdapter()
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766", adapter=self.adapter)
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_duplicate_intent_does_not_repeat_the_adapter_call(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "dup-1", "idempotency_key": "dup-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        _, first = self.bob.accept(envelope)
        _, second = self.bob.accept(envelope)  # same message_id -> transport-level dedup
        self.assertEqual(first, second)
        self.assertEqual(self.adapter.calls, 1)

        # A distinct envelope re-proposing the SAME idempotency_key must
        # also not repeat the effect -- the application-level (not
        # transport-level) idempotency guarantee.
        resubmitted = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "dup-1", "idempotency_key": "dup-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        _, third = self.bob.accept(resubmitted)
        self.assertEqual(third, first)
        self.assertEqual(self.adapter.calls, 1)

    def test_task_row_reaches_completed_state(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "state-1", "idempotency_key": "state-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        self.bob.accept(envelope)
        self.assertEqual(self.bob.tasks.get("state-1")["state"], "COMPLETED")

    def test_stale_running_lease_is_resolved_to_failed_on_restart(self) -> None:
        """Simulates a process crash mid-adapter-call: a row is left RUNNING
        with an already-expired lease, then the harness is reopened."""
        self.bob.tasks.propose("stuck-1", "stuck-1", "observe.system.status.v1", self.alice.identity.system_id, "2000-01-01T00:00:00.000Z")
        self.bob.tasks.start_running("stuck-1", lease_until="2000-01-01T00:00:01.000Z", at="2000-01-01T00:00:00.000Z")
        self.assertEqual(self.bob.tasks.get("stuck-1")["state"], "RUNNING")

        reopened_bob = FaspHarness(Path(self.bob.state.directory), "bob", "http://bob:8766")
        task = reopened_bob.tasks.get("stuck-1")
        self.assertEqual(task["state"], "FAILED")
        self.assertEqual(task["error"]["code"], "lease.expired")

    def test_rejected_intent_is_recorded_and_a_duplicate_returns_the_same_rejection(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "reject-1", "idempotency_key": "reject-1", "capability": "observe.system.status.v1", "risk": "external",
        })
        with self.assertRaises(FaspError) as first_raise:
            self.bob.accept(envelope)
        self.assertEqual(self.bob.tasks.get("reject-1")["state"], "REJECTED")

        resubmitted = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "reject-1", "idempotency_key": "reject-1", "capability": "observe.system.status.v1", "risk": "external",
        })
        with self.assertRaises(FaspError) as second_raise:
            self.bob.accept(resubmitted)
        self.assertEqual(first_raise.exception.code, second_raise.exception.code)
        self.assertEqual(self.adapter.calls, 0)


if __name__ == "__main__":
    unittest.main()
