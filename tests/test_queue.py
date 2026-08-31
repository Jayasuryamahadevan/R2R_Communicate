"""Phase 9/10 conformance: universal replay dedup across every envelope
kind (not just intent.propose), the bounded adapter work queue's real
wall-clock timeout, durable backpressure, and task.status polling."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness


class _BlockingAdapter(DefaultSafeAdapter):
    """Blocks inside handle() until released -- used to force the bounded
    executor's synchronous wait to time out, and to hold a slot open long
    enough to observe backpressure."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered_handle = threading.Event()

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.entered_handle.set()
        self.release.wait(timeout=5)
        return super().handle(intent)


class QueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.alice.close()
        self.bob.close()

    def _paired(self, adapter: Any = None, prefixes: list[str] | None = None, **bob_kwargs: Any) -> tuple[FaspHarness, FaspHarness]:
        self.alice = FaspHarness(self.root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(self.root / "bob", "bob", "http://bob:8766", adapter=adapter, **bob_kwargs)
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"], prefixes)
        return self.alice, self.bob

    def test_duplicate_reservation_request_is_never_reprocessed(self) -> None:
        """A retried envelope (same message_id) must return the exact
        original response -- not a second, independently-processed one.
        `ReservationBook.request()` mints a fresh random reservation_id
        whenever the payload omits one, so a real double-process would be
        caught here: two calls would almost certainly disagree."""
        alice, bob = self._paired(prefixes=["fleet."])
        start = int(time.time() * 1000) + 1_000
        envelope = alice.make_envelope("reservation.request", bob.identity.system_id, {
            "segments": [{"cell": "hall-1", "start_ms": start, "end_ms": start + 5_000}],
        })
        first = bob.reservation_request(envelope)
        second = bob.reservation_request(envelope)
        self.assertEqual(first, second)
        self.assertEqual(first["type"], "reservation.grant")

    def test_duplicate_heartbeat_returns_the_identical_cached_response(self) -> None:
        alice, bob = self._paired()
        envelope = alice.make_envelope("heartbeat", bob.identity.system_id, {})
        first = bob.heartbeat(envelope)
        second = bob.heartbeat(envelope)
        # Same message_id -> same cached response, including server_time,
        # rather than a fresh timestamp from actually re-running the call.
        self.assertEqual(first, second)

    def test_slow_adapter_returns_progress_then_task_status_reports_completion(self) -> None:
        adapter = _BlockingAdapter()
        alice, bob = self._paired(adapter)
        propose = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "slow-status-1", "idempotency_key": "slow-status-1", "capability": "observe.system.status.v1", "risk": "observe",
        })

        # The capability's own max_runtime_s (5s in DefaultSafeAdapter) caps
        # the synchronous wait; monkeypatch a near-zero lease so the test
        # doesn't need to actually block for 5 seconds.
        original_capabilities = adapter.capabilities

        def fast_lease_capabilities() -> list[dict[str, Any]]:
            capabilities = original_capabilities()
            for item in capabilities:
                if item["id"] == "observe.system.status.v1":
                    item["max_runtime_s"] = 0.05
            return capabilities

        adapter.capabilities = fast_lease_capabilities  # type: ignore[method-assign]

        _, response = bob.accept(propose)
        self.assertEqual(response["status"], "running")
        self.assertEqual(response["type"], "task.progress")

        adapter.release.set()
        status_envelope = alice.make_envelope("task.status", bob.identity.system_id, {"idempotency_key": "slow-status-1"})

        def eventually_completed() -> bool:
            for _ in range(200):
                status = bob.task_status(alice.make_envelope("task.status", bob.identity.system_id, {"idempotency_key": "slow-status-1"}))
                if status["status"] == "completed":
                    return True
                time.sleep(0.01)
            return False

        self.assertTrue(eventually_completed())
        final = bob.task_status(status_envelope)
        self.assertEqual(final["status"], "completed")

    def test_backpressure_rejects_new_intents_once_the_queue_is_at_capacity(self) -> None:
        adapter = _BlockingAdapter()
        alice, bob = self._paired(adapter, max_inflight_tasks=1)
        first = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "cap-1", "idempotency_key": "cap-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        thread = threading.Thread(target=bob.accept, args=(first,))
        thread.start()
        self.assertTrue(adapter.entered_handle.wait(timeout=5))

        second = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "cap-2", "idempotency_key": "cap-2", "capability": "observe.system.status.v1", "risk": "observe",
        })
        with self.assertRaises(FaspError) as raised:
            bob.accept(second)
        self.assertEqual(raised.exception.code, "resource.exhausted")

        adapter.release.set()
        thread.join(timeout=5)

    def test_task_status_rejects_an_unknown_or_foreign_idempotency_key(self) -> None:
        alice, bob = self._paired()
        carol = FaspHarness(self.root / "carol", "carol", "http://carol:8766")
        hello = bob.hello(carol.id_card())
        bob.confirm_peer(carol.identity.system_id, hello["pair_code"])
        try:
            propose = alice.make_envelope("intent.propose", bob.identity.system_id, {
                "intent_id": "owned-by-alice", "idempotency_key": "owned-by-alice", "capability": "observe.system.status.v1", "risk": "observe",
            })
            bob.accept(propose)

            foreign_status = carol.make_envelope("task.status", bob.identity.system_id, {"idempotency_key": "owned-by-alice"})
            with self.assertRaises(FaspError) as raised:
                bob.task_status(foreign_status)
            self.assertEqual(raised.exception.code, "schema.invalid")
        finally:
            carol.close()


if __name__ == "__main__":
    unittest.main()
