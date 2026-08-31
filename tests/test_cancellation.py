"""Conformance #7 (FASP_PROTOCOL.md ss15): cancellation-before-effect vs
cancellation-too-late.

Uses real threads (not mocked time) since the harness's optimistic-
concurrency task transitions are meant to resolve a genuine race between a
propose call still inside adapter.handle() and a concurrent task.cancel.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness


class _SlowAdapter(DefaultSafeAdapter):
    """Blocks inside handle() until released, so a concurrent task.cancel
    can genuinely race against it on a separate thread."""

    def __init__(self, accept_cancel: bool) -> None:
        self._accept_cancel = accept_cancel
        self.release = threading.Event()
        self.entered_handle = threading.Event()
        self.cancel_called = threading.Event()

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.entered_handle.set()
        self.release.wait(timeout=5)
        return super().handle(intent)

    def cancel(self, idempotency_key: str) -> bool:
        self.cancel_called.set()
        return self._accept_cancel


class CancellationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _paired_harnesses(self, adapter: Any) -> tuple[FaspHarness, FaspHarness]:
        alice = FaspHarness(self.root / "alice", "alice", "http://alice:8766")
        bob = FaspHarness(self.root / "bob", "bob", "http://bob:8766", adapter=adapter)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
        return alice, bob

    def test_cancel_while_running_and_adapter_accepts_is_cancelled(self) -> None:
        adapter = _SlowAdapter(accept_cancel=True)
        alice, bob = self._paired_harnesses(adapter)
        propose = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "slow-1", "idempotency_key": "slow-1", "capability": "observe.system.status.v1", "risk": "observe",
        })

        thread = threading.Thread(target=bob.accept, args=(propose,))
        thread.start()
        self.assertTrue(adapter.entered_handle.wait(timeout=5))

        cancel = alice.make_envelope("task.cancel", bob.identity.system_id, {"idempotency_key": "slow-1"})
        _, cancel_response = bob.accept(cancel)
        self.assertEqual(cancel_response["type"], "task.cancelled")
        self.assertTrue(adapter.cancel_called.wait(timeout=5))

        adapter.release.set()
        thread.join(timeout=5)
        self.assertEqual(bob.tasks.get("slow-1")["state"], "CANCELLED")

    def test_cancel_while_running_and_adapter_declines_is_too_late(self) -> None:
        adapter = _SlowAdapter(accept_cancel=False)
        alice, bob = self._paired_harnesses(adapter)
        propose = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "slow-2", "idempotency_key": "slow-2", "capability": "observe.system.status.v1", "risk": "observe",
        })

        results: dict[str, Any] = {}

        def run_propose() -> None:
            results["propose"] = bob.accept(propose)

        thread = threading.Thread(target=run_propose)
        thread.start()
        self.assertTrue(adapter.entered_handle.wait(timeout=5))

        cancel = alice.make_envelope("task.cancel", bob.identity.system_id, {"idempotency_key": "slow-2"})
        _, cancel_response = bob.accept(cancel)
        self.assertEqual(cancel_response["type"], "task.too_late")
        self.assertEqual(cancel_response["status"], "running")

        adapter.release.set()
        thread.join(timeout=5)
        self.assertEqual(bob.tasks.get("slow-2")["state"], "COMPLETED")
        self.assertEqual(results["propose"][1]["status"], "completed")

    def test_cancel_before_running_is_cancelled_immediately(self) -> None:
        alice, bob = self._paired_harnesses(DefaultSafeAdapter())
        # Directly insert a PROPOSED row (bypassing the synchronous propose
        # path, which never leaves an externally-observable PROPOSED window
        # on its own) to exercise the "cancel before any effect" branch.
        bob.tasks.propose("early-1", "early-1", "observe.system.status.v1", alice.identity.system_id, "2026-01-01T00:00:00.000Z")
        cancel = alice.make_envelope("task.cancel", bob.identity.system_id, {"idempotency_key": "early-1"})
        _, cancel_response = bob.accept(cancel)
        self.assertEqual(cancel_response["type"], "task.cancelled")
        self.assertEqual(bob.tasks.get("early-1")["state"], "CANCELLED")

    def test_cancel_after_completion_is_too_late(self) -> None:
        alice, bob = self._paired_harnesses(DefaultSafeAdapter())
        propose = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "done-1", "idempotency_key": "done-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        bob.accept(propose)
        cancel = alice.make_envelope("task.cancel", bob.identity.system_id, {"idempotency_key": "done-1"})
        _, cancel_response = bob.accept(cancel)
        self.assertEqual(cancel_response["type"], "task.too_late")
        self.assertEqual(cancel_response["status"], "completed")

    def test_only_the_proposing_peer_may_cancel(self) -> None:
        alice, bob = self._paired_harnesses(DefaultSafeAdapter())
        carol = FaspHarness(self.root / "carol", "carol", "http://carol:8766")
        hello = bob.hello(carol.id_card())
        bob.confirm_peer(carol.identity.system_id, hello["pair_code"])

        bob.tasks.propose("owned-by-alice", "owned-by-alice", "observe.system.status.v1", alice.identity.system_id, "2026-01-01T00:00:00.000Z")
        cancel = carol.make_envelope("task.cancel", bob.identity.system_id, {"idempotency_key": "owned-by-alice"})
        with self.assertRaises(FaspError) as raised:
            bob.accept(cancel)
        self.assertEqual(raised.exception.code, "auth.not_authorized")


if __name__ == "__main__":
    unittest.main()
