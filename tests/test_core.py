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


if __name__ == "__main__":
    unittest.main()
