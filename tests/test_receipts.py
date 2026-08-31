"""Conformance #4 (FASP_PROTOCOL.md ss15): distinguish relay/delivery,
recipient processing, and terminal completion in the API.

No schema change was needed for this: the existing design already keeps
these four signals separate --
  - `receipt.delivered` (server.py wraps every accept() response in this):
    the transport-level confirmation that this system received the envelope.
  - `duplicate` / `response` returned alongside it: whether this exact
    envelope had already been processed, and what (if anything) resulted.
  - `task.result` / `task.fail`: the terminal completion signal for a
    proposed intent specifically.
  - `receipt.processed`: a separate, explicit application-level
    acknowledgement the RECEIVING peer can send back about a non-intent
    message it has finished handling.
This test only pins that distinction down so a future change can't quietly
collapse it.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness


class ReceiptsConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        # Mutual pairing: alice must also know bob to accept an envelope
        # FROM bob (each harness keeps its own independent peers table).
        hello_back = self.alice.hello(self.bob.id_card())
        self.alice.confirm_peer(self.bob.identity.system_id, hello_back["pair_code"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_delivery_and_task_completion_are_distinct_signals(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "receipt-1", "idempotency_key": "receipt-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        duplicate, response = self.bob.accept(envelope)
        self.assertFalse(duplicate)
        self.assertEqual(response["type"], "task.result")
        self.assertEqual(response["status"], "completed")

    def test_non_intent_delivery_carries_no_task_response(self) -> None:
        chat = self.alice.make_envelope("coordinate.chat.v1", self.bob.identity.system_id, {"note": "hello"})
        duplicate, response = self.bob.accept(chat)
        self.assertFalse(duplicate)
        self.assertIsNone(response)

    def test_receipt_processed_is_a_distinct_application_level_acknowledgement(self) -> None:
        chat = self.alice.make_envelope("coordinate.chat.v1", self.bob.identity.system_id, {"note": "hello"})
        self.bob.accept(chat)

        receipt_envelope = self.bob.make_envelope("receipt.processed", self.alice.identity.system_id, {"message_id": chat["message_id"]})
        result = self.alice.receipt(receipt_envelope)
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
