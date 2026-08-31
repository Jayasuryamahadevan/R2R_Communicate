from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspError, FaspHarness


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def pair_alice_to_bob(self) -> None:
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])

    def test_signed_id_card_rejects_tampering(self) -> None:
        card = self.alice.id_card()
        FaspHarness.verify_id_card(card)
        altered = copy.deepcopy(card)
        altered["display_name"] = "impostor"
        with self.assertRaises(FaspError) as raised:
            FaspHarness.verify_id_card(altered)
        self.assertEqual(raised.exception.code, "auth.invalid_signature")

    def test_pairing_and_idempotent_task(self) -> None:
        self.pair_alice_to_bob()
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "status-1",
            "idempotency_key": "status-1",
            "capability": "observe.system.status.v1",
            "objective": "Check service state",
            "risk": "observe",
        })
        duplicate, result = self.bob.accept(envelope)
        self.assertFalse(duplicate)
        self.assertEqual(result["status"], "completed")
        duplicate, repeated = self.bob.accept(envelope)
        self.assertTrue(duplicate)
        self.assertEqual(result, repeated)

    def test_unpaired_sender_is_rejected(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "idempotency_key": "unpaired", "capability": "observe.system.status.v1", "risk": "observe",
        })
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(envelope)
        self.assertEqual(raised.exception.code, "auth.not_paired")

    def test_policy_blocks_external_risk(self) -> None:
        self.pair_alice_to_bob()
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "idempotency_key": "external", "capability": "observe.system.status.v1", "risk": "external",
        })
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(envelope)
        self.assertEqual(raised.exception.code, "policy.requires_confirmation")

    def test_pairing_and_task_result_survive_reopening_the_harness(self) -> None:
        """The SQLite-backed peers/tasks state must be durable across process restarts, not just in-memory."""
        self.pair_alice_to_bob()
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "status-durable",
            "idempotency_key": "status-durable",
            "capability": "observe.system.status.v1",
            "objective": "Check service state",
            "risk": "observe",
        })
        _, first_result = self.bob.accept(envelope)

        reopened_bob = FaspHarness(Path(self.bob.state.directory), "bob", "http://bob:8766")
        self.assertEqual(reopened_bob.identity.system_id, self.bob.identity.system_id)
        duplicate, replayed_result = reopened_bob.accept(envelope)
        self.assertTrue(duplicate)
        self.assertEqual(replayed_result, first_result)

    def test_inbox_pull_is_scoped_to_the_requesting_peer(self) -> None:
        """A paired peer must only see envelopes it sent itself, not another peer's."""
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://carol:8766")
        self.pair_alice_to_bob()
        hello = self.bob.hello(carol.id_card())
        self.bob.confirm_peer(carol.identity.system_id, hello["pair_code"])

        alice_envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "idempotency_key": "alice-status", "capability": "observe.system.status.v1", "risk": "observe",
        })
        self.bob.accept(alice_envelope)

        carol_pull = carol.make_envelope("inbox.pull", self.bob.identity.system_id, {"cursor": 0})
        carol_inbox = self.bob.pull_inbox(carol_pull)
        self.assertEqual(carol_inbox["messages"], [])

        alice_pull = self.alice.make_envelope("inbox.pull", self.bob.identity.system_id, {"cursor": 0})
        alice_inbox = self.bob.pull_inbox(alice_pull)
        self.assertEqual([item["message_id"] for item in alice_inbox["messages"]], [alice_envelope["message_id"]])


if __name__ == "__main__":
    unittest.main()
