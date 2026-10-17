"""Regression tests for restart/interruption hardening.

These cover the seams where an interrupted process used to be able to wedge
the protocol or leak an adapter bug:

* a non-JSON adapter result failing the task instead of escaping as a 500
  (which also left the row RUNNING and the envelope unanswerable);
* a raising adapter `cancel` hook declining the cancel instead of leaking
  and leaving cancel_requested behind;
* a duplicate proposal racing a running adapter getting a pollable
  `task.progress` instead of a schema error;
* an intent stranded between admission and start_running by a crash being
  re-driven by a retry envelope or by the reconciler sweep, instead of
  occupying admission capacity forever;
* an envelope admitted but never answered by a crashed process being
  re-dispatched instead of returning `transport.response_unavailable`
  forever;
* concurrent duplicates of an in-flight envelope getting the retryable
  "still processing" answer, not a double execution;
* receipt bookkeeping not losing concurrent writes;
* a reservation id minted deterministically so a re-dispatch resolves to
  the same reservation;
* absurdly nested JSON becoming a clean schema rejection.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness
from fasp_harness.streaming import StreamRegistry
from fasp_harness.timestamps import now, stamp


class _CountingAdapter(DefaultSafeAdapter):
    def __init__(self) -> None:
        self.calls = 0

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return super().handle(intent)


class _BadOutputAdapter(DefaultSafeAdapter):
    def __init__(self, output: Any) -> None:
        self.output = output
        self.calls = 0

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return self.output


class _SlowAdapter(DefaultSafeAdapter):
    def __init__(self) -> None:
        self.entered_handle = threading.Event()
        self.release = threading.Event()

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.entered_handle.set()
        self.release.wait(timeout=5)
        return super().handle(intent)


class _RaisingCancelAdapter(_SlowAdapter):
    def cancel(self, idempotency_key: str) -> bool:
        raise RuntimeError("adapter cancel bug")


class _LimitedAdapter(DefaultSafeAdapter):
    """A restarted process that no longer offers every old capability."""

    def capabilities(self) -> list[dict[str, Any]]:
        return [{"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 5, "network": "none"}]


def _intent(key: str = "i-1", capability: str = "observe.system.status.v1") -> dict[str, Any]:
    return {"intent_id": key, "idempotency_key": key, "capability": capability, "risk": "observe"}


class RecoveryHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _paired(self, adapter: Any | None = None, prefixes: list[str] | None = None) -> tuple[FaspHarness, FaspHarness]:
        alice = FaspHarness(self.root / "alice", "alice", "http://alice:8766")
        bob = FaspHarness(self.root / "bob", "bob", "http://bob:8766", adapter=adapter)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"], prefixes)
        return alice, bob

    # -- adapter bugs never leak --------------------------------------------

    def test_nan_adapter_output_fails_the_task_instead_of_leaking(self) -> None:
        adapter = _BadOutputAdapter({"value": float("nan")})
        alice, bob = self._paired(adapter)
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, _intent("nan-1"))
        _, response = bob.accept(envelope)
        self.assertEqual(response["type"], "task.fail")
        self.assertEqual(response["error"]["code"], "internal.adapter_error")
        self.assertEqual(bob.tasks.get("nan-1")["state"], "FAILED")
        # The exact envelope replays to the same recorded failure.
        _, replay = bob.accept(envelope)
        self.assertEqual(replay, response)
        self.assertEqual(adapter.calls, 1)

    def test_non_json_adapter_output_fails_the_task_instead_of_leaking(self) -> None:
        adapter = _BadOutputAdapter({"value": {1, 2, 3}})
        alice, bob = self._paired(adapter)
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, _intent("set-1"))
        _, response = bob.accept(envelope)
        self.assertEqual(response["type"], "task.fail")
        self.assertEqual(response["error"]["code"], "internal.adapter_error")
        self.assertEqual(bob.tasks.get("set-1")["state"], "FAILED")

    def test_raising_cancel_hook_declines_instead_of_leaving_cancel_pending(self) -> None:
        adapter = _RaisingCancelAdapter()
        alice, bob = self._paired(adapter)
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, _intent("slow-cancel"))
        results: list[Any] = []
        thread = threading.Thread(target=lambda: results.append(bob.accept(envelope)))
        thread.start()
        self.assertTrue(adapter.entered_handle.wait(timeout=5))

        cancel = alice.make_envelope("task.cancel", bob.identity.system_id, {"idempotency_key": "slow-cancel"})
        _, response = bob.accept(cancel)
        self.assertEqual(response["type"], "task.too_late")
        self.assertEqual(response["status"], "running")
        task = bob.tasks.get("slow-cancel")
        self.assertEqual(task["state"], "RUNNING")
        self.assertNotEqual(task.get("phase"), "cancel_requested")

        adapter.release.set()
        thread.join(timeout=5)
        self.assertEqual(bob.tasks.get("slow-cancel")["state"], "COMPLETED")
        self.assertEqual(results[0][1]["status"], "completed")

    # -- duplicates while running -------------------------------------------

    def test_duplicate_while_running_returns_progress_not_an_error(self) -> None:
        adapter = _SlowAdapter()
        alice, bob = self._paired(adapter)
        intent = _intent("running-dup")
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, intent)
        thread = threading.Thread(target=bob.accept, args=(envelope,))
        thread.start()
        self.assertTrue(adapter.entered_handle.wait(timeout=5))

        duplicate = alice.make_envelope("intent.propose", bob.identity.system_id, intent)
        _, response = bob.accept(duplicate)
        self.assertEqual(response["type"], "task.progress")
        self.assertEqual(response["status"], "running")

        adapter.release.set()
        thread.join(timeout=5)
        _, outcome = bob.accept(envelope)
        self.assertEqual(outcome["status"], "completed")

    # -- stranded work recovery ---------------------------------------------

    def test_retry_envelope_revives_a_stranded_queued_intent(self) -> None:
        adapter = _CountingAdapter()
        alice, bob = self._paired(adapter)
        intent = _intent("stranded-1")
        # Simulate the crash window: the row was admitted, the adapter was
        # never reached, and the admitting process is gone.
        self.assertTrue(bob.tasks.propose("stranded-1", "stranded-1", "observe.system.status.v1", alice.identity.system_id, stamp(), payload=intent))
        self.assertEqual(bob.tasks.count_inflight(), 1)

        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, intent)
        _, response = bob.accept(envelope)
        self.assertEqual(response["status"], "completed")
        self.assertEqual(bob.tasks.get("stranded-1")["state"], "COMPLETED")
        self.assertEqual(adapter.calls, 1)
        # The stranded row no longer consumes durable admission capacity.
        self.assertEqual(bob.tasks.count_inflight(), 0)

    def test_retry_envelope_revives_a_legacy_row_without_a_stored_payload(self) -> None:
        adapter = _CountingAdapter()
        alice, bob = self._paired(adapter)
        intent = _intent("legacy-1")
        # A row admitted by an older harness that did not persist payloads.
        self.assertTrue(bob.tasks.propose("legacy-1", "legacy-1", "observe.system.status.v1", alice.identity.system_id, stamp(), payload=None))

        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, intent)
        _, response = bob.accept(envelope)
        self.assertEqual(response["status"], "completed")
        self.assertEqual(adapter.calls, 1)

    def test_sweep_fails_a_stranded_row_that_has_no_stored_payload(self) -> None:
        alice, bob = self._paired(_CountingAdapter())
        old = stamp(now() - timedelta(hours=1))
        self.assertTrue(bob.tasks.propose("legacy-2", "legacy-2", "observe.system.status.v1", alice.identity.system_id, old, payload=None))

        result = bob.recover_interrupted_intents(older_than_seconds=60)
        self.assertEqual(result["checked"], 1)
        record = bob.tasks.get("legacy-2")
        self.assertEqual(record["state"], "REJECTED")
        self.assertEqual(record["error"]["code"], "task.interrupted")

    def test_reconciler_sweep_revives_a_stranded_queued_intent(self) -> None:
        adapter = _CountingAdapter()
        alice, bob = self._paired(adapter)
        intent = _intent("stranded-2")
        old = stamp(now() - timedelta(hours=1))
        self.assertTrue(bob.tasks.propose("stranded-2", "stranded-2", "observe.system.status.v1", alice.identity.system_id, old, payload=intent))

        result = bob.recover_interrupted_intents(older_than_seconds=60)
        self.assertEqual(result, {"checked": 1, "recovered": 1})
        self.assertEqual(bob.tasks.get("stranded-2")["state"], "COMPLETED")
        self.assertEqual(adapter.calls, 1)
        # A freshly queued row is inside its admission window and untouched.
        fresh = _intent("fresh-1")
        self.assertTrue(bob.tasks.propose("fresh-1", "fresh-1", "observe.system.status.v1", alice.identity.system_id, stamp(), payload=fresh))
        self.assertEqual(bob.recover_interrupted_intents(older_than_seconds=60), {"checked": 0, "recovered": 0})
        self.assertEqual(bob.tasks.get("fresh-1")["state"], "PROPOSED")

    def test_sweep_rejects_stranded_work_from_a_revoked_peer(self) -> None:
        alice, bob = self._paired(_CountingAdapter())
        intent = _intent("stranded-3")
        old = stamp(now() - timedelta(hours=1))
        bob.tasks.propose("stranded-3", "stranded-3", "observe.system.status.v1", alice.identity.system_id, old, payload=intent)
        bob.revoke_peer(alice.identity.system_id, "test revocation")

        result = bob.recover_interrupted_intents(older_than_seconds=60)
        self.assertEqual(result["checked"], 1)
        task = bob.tasks.get("stranded-3")
        self.assertEqual(task["state"], "REJECTED")
        self.assertEqual(task["error"]["code"], "auth.peer_revoked")

    def test_sweep_revalidates_a_stranded_intent_against_current_capabilities(self) -> None:
        alice, bob = self._paired(_CountingAdapter())
        intent = _intent("stranded-4", capability="coordinate.chat.v1")
        old = stamp(now() - timedelta(hours=1))
        bob.tasks.propose("stranded-4", "stranded-4", "coordinate.chat.v1", alice.identity.system_id, old, payload=intent)

        # A restarted process whose adapter no longer offers that capability.
        restarted = FaspHarness(self.root / "bob", "bob", "http://bob:8766", adapter=_LimitedAdapter())
        result = restarted.recover_interrupted_intents(older_than_seconds=60)
        self.assertEqual(result["checked"], 1)
        task = restarted.tasks.get("stranded-4")
        self.assertEqual(task["state"], "REJECTED")
        self.assertEqual(task["error"]["code"], "capability.unavailable")
        restarted.close()

    # -- envelopes interrupted after admission ------------------------------

    def test_envelope_admitted_but_unanswered_is_re_driven(self) -> None:
        adapter = _CountingAdapter()
        alice, bob = self._paired(adapter)
        intent = _intent("crash-1")
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, intent)
        # Simulate: admission committed, then the process died before the
        # response was recorded.
        self.assertTrue(bob.inbox.insert_if_new(envelope, stamp()))
        self.assertIsNone(bob.inbox.get_response(envelope["message_id"]))

        _, response = bob.accept(envelope)
        self.assertEqual(response["status"], "completed")
        self.assertEqual(adapter.calls, 1)
        # And now it is a normal replay: recorded response, no second effect.
        _, again = bob.accept(envelope)
        self.assertEqual(again, response)
        self.assertEqual(adapter.calls, 1)

    def test_unanswered_read_only_envelope_is_re_driven_and_recorded(self) -> None:
        alice, bob = self._paired(_CountingAdapter())
        envelope = alice.make_envelope("receipt.processed", bob.identity.system_id, {"message_id": "peer-msg-7"})
        self.assertTrue(bob.inbox.insert_if_new(envelope, stamp()))

        _, response = bob.accept(envelope)
        self.assertEqual(response, {"ok": True})
        receipts = bob.state.get("receipts.json", {})
        self.assertIn("peer-msg-7", receipts)
        _, again = bob.accept(envelope)
        self.assertEqual(again, response)

    def test_concurrent_duplicate_gets_the_retryable_in_progress_answer(self) -> None:
        adapter = _SlowAdapter()
        alice, bob = self._paired(adapter)
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, _intent("inflight-1"))
        results: list[Any] = []
        thread = threading.Thread(target=lambda: results.append(bob.accept(envelope)))
        thread.start()
        self.assertTrue(adapter.entered_handle.wait(timeout=5))

        seen, response = bob.accept(envelope)
        self.assertTrue(seen)
        self.assertIsNone(response)  # transport maps this to 503 + Retry-After

        adapter.release.set()
        thread.join(timeout=5)
        self.assertEqual(results[0][1]["status"], "completed")
        _, replay = bob.accept(envelope)
        self.assertEqual(replay["status"], "completed")

    # -- deterministic reservation ids --------------------------------------

    def test_auto_reservation_id_is_stable_across_a_redispatch(self) -> None:
        alice, bob = self._paired(_CountingAdapter(), prefixes=["fleet."])
        start = int(time.time() * 1000) + 1_000
        envelope = alice.make_envelope(
            "reservation.request",
            bob.identity.system_id,
            {"lease_ms": 30_000, "segments": [{"cell": "aisle-9/cell-1", "start_ms": start, "end_ms": start + 5_000}]},
        )
        # Crash after the effect committed but before the response landed.
        self.assertTrue(bob.inbox.insert_if_new(envelope, stamp()))
        first = bob.reservation_request(envelope)
        self.assertEqual(first["type"], "reservation.grant")
        self.assertTrue(first["reservation_id"].startswith("auto-"))

        # Force another re-dispatch of the same envelope and confirm it
        # resolves to the same reservation rather than minting a second one.
        bob.inbox.set_response(envelope["message_id"], None)
        second = bob.reservation_request(envelope)
        self.assertEqual(second["reservation_id"], first["reservation_id"])
        count = bob.db.read_one("SELECT COUNT(*) AS n FROM reservations")
        self.assertEqual(count["n"], 1)

    # -- bounded / atomic local bookkeeping ---------------------------------

    def test_concurrent_receipt_writes_do_not_lose_entries(self) -> None:
        alice, bob = self._paired(_CountingAdapter())
        with self.assertRaises(FaspError):
            bob._handle_receipt({"payload": {"message_id": None}, "from": "peer"}, {})

        def worker(offset: int) -> None:
            for index in range(25):
                bob._handle_receipt({"payload": {"message_id": f"m-{offset}-{index}"}, "from": "peer-x"}, {})

        threads = [threading.Thread(target=worker, args=(offset,)) for offset in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        receipts = bob.state.get("receipts.json", {})
        self.assertEqual(len(receipts), 8 * 25)
        self.assertIn("m-7-24", receipts)

    # -- absurd JSON nesting ------------------------------------------------

    def test_absurdly_nested_json_record_is_a_clean_rejection(self) -> None:
        depth = 200_000
        payload = ('{"a":' * depth) + "1" + "}" * depth
        try:
            json.loads(payload)
        except RecursionError:
            pass
        else:
            self.skipTest("this platform's JSON parser tolerates the nesting depth")
        with self.assertRaises(FaspError) as raised:
            StreamRegistry._validate_json_record({"fragment_count": 1, "fragment_index": 0}, {"fields": ["a"]}, payload.encode("utf-8"))
        self.assertEqual(raised.exception.code, "stream.invalid_json")


if __name__ == "__main__":
    unittest.main()
