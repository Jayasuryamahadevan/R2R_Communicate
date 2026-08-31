"""Conformance #10 (FASP_PROTOCOL.md ss15): demonstrate key revocation and re-pairing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import FaspError, FaspHarness


class RevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _status_envelope(self, key: str) -> dict[str, Any]:
        return self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": key, "idempotency_key": key, "capability": "observe.system.status.v1", "risk": "observe",
        })

    def test_revoked_peer_is_rejected_even_though_still_marked_paired(self) -> None:
        duplicate, result = self.bob.accept(self._status_envelope("before-revoke"))
        self.assertFalse(duplicate)
        self.assertEqual(result["status"], "completed")

        self.bob.revoke_peer(self.alice.identity.system_id, "suspected key compromise")
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._status_envelope("after-revoke"))
        self.assertEqual(raised.exception.code, "auth.peer_revoked")

    def test_re_pairing_clears_a_revocation(self) -> None:
        self.bob.revoke_peer(self.alice.identity.system_id, "suspected key compromise")
        with self.assertRaises(FaspError):
            self.bob.accept(self._status_envelope("still-revoked"))

        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        duplicate, result = self.bob.accept(self._status_envelope("after-re-pair"))
        self.assertFalse(duplicate)
        self.assertEqual(result["status"], "completed")

    def test_expired_pairing_requires_re_pairing(self) -> None:
        # setUp already paired with a 90-day validity window; simulate its
        # expiry directly rather than waiting 90 days.
        with self.bob.db.write() as conn:
            conn.execute("UPDATE peers SET expires_at = '2000-01-01T00:00:00.000Z' WHERE peer_id = ?", (self.alice.identity.system_id,))

        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._status_envelope("expired-pairing"))
        self.assertEqual(raised.exception.code, "auth.pairing_expired")

        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        duplicate, result = self.bob.accept(self._status_envelope("after-re-pair"))
        self.assertFalse(duplicate)
        self.assertEqual(result["status"], "completed")


if __name__ == "__main__":
    unittest.main()
