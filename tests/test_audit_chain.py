"""The append-only audit log must be internally verifiable (FASP_PROTOCOL.md ss11)."""

from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fasp_harness.core import FaspHarness


class AuditChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_chain_verifies_after_pairing_grants_and_tasks(self) -> None:
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        grant = self.bob.issue_grant(self.alice.identity.system_id, ["observe."], timedelta(minutes=5))
        self.bob.revoke_grant(grant["grant_id"])
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "audit-1", "idempotency_key": "audit-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        self.bob.accept(envelope)
        self.bob.revoke_peer(self.alice.identity.system_id, "test revoke")

        ok, bad_seq = self.bob.audit.verify()
        self.assertTrue(ok)
        self.assertIsNone(bad_seq)

    def test_tampering_with_a_row_is_detected(self) -> None:
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        with self.bob.db.write() as conn:
            conn.execute("UPDATE audit_log SET detail_json = ? WHERE seq = 1", ('{"tampered":true}',))
        ok, bad_seq = self.bob.audit.verify()
        self.assertFalse(ok)
        self.assertEqual(bad_seq, 1)


if __name__ == "__main__":
    unittest.main()
