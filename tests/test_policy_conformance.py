"""Conformance #2 (FASP_PROTOCOL.md ss15): reject a validly signed request
lacking a matching grant, once the referenced capability's risk class
requires one (ss3.3, ss8)."""

from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness


class _ReversibleAdapter(DefaultSafeAdapter):
    """Exposes one `reversible`-risk capability.

    The shipped DefaultSafeAdapter only offers `observe`-risk capabilities
    (which never require a grant), so it can't exercise the grant-required
    policy path on its own.
    """

    def capabilities(self) -> list[dict[str, Any]]:
        return [*super().capabilities(), {"id": "reversible.workspace.draft.v1", "risk": "reversible", "max_runtime_s": 5, "network": "none"}]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        if intent.get("capability") == "reversible.workspace.draft.v1":
            return {"status": "ok", "draft": True}
        return super().handle(intent)


class PolicyConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766", adapter=_ReversibleAdapter())
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766", adapter=_ReversibleAdapter())
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"], ["observe.", "coordinate.", "reversible."])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _draft_envelope(self, grant_id: str | None, key: str = "draft-1") -> dict[str, Any]:
        payload: dict[str, Any] = {
            "intent_id": key,
            "idempotency_key": key,
            "capability": "reversible.workspace.draft.v1",
            "objective": "Stage a draft",
            "risk": "reversible",
        }
        if grant_id is not None:
            payload["grant"] = {"id": grant_id}
        return self.alice.make_envelope("intent.propose", self.bob.identity.system_id, payload)

    def test_signed_request_without_a_grant_is_rejected(self) -> None:
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._draft_envelope(None))
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_valid_grant_authorizes_the_reversible_capability(self) -> None:
        grant = self.bob.issue_grant(self.alice.identity.system_id, ["reversible."], timedelta(minutes=5))
        duplicate, result = self.bob.accept(self._draft_envelope(grant["grant_id"]))
        self.assertFalse(duplicate)
        self.assertEqual(result["status"], "completed")

    def test_revoked_grant_is_rejected(self) -> None:
        grant = self.bob.issue_grant(self.alice.identity.system_id, ["reversible."], timedelta(minutes=5))
        self.bob.revoke_grant(grant["grant_id"])
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._draft_envelope(grant["grant_id"]))
        self.assertEqual(raised.exception.code, "auth.grant_expired")

    def test_expired_grant_is_rejected(self) -> None:
        grant = self.bob.issue_grant(self.alice.identity.system_id, ["reversible."], timedelta(seconds=-1))
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._draft_envelope(grant["grant_id"]))
        self.assertEqual(raised.exception.code, "auth.grant_expired")

    def test_grant_issued_to_a_different_peer_does_not_authorize(self) -> None:
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://carol:8766")
        hello = self.bob.hello(carol.id_card())
        self.bob.confirm_peer(carol.identity.system_id, hello["pair_code"])
        grant = self.bob.issue_grant(carol.identity.system_id, ["reversible."], timedelta(minutes=5))
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._draft_envelope(grant["grant_id"]))
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_grant_never_widens_beyond_the_peers_pairing_prefixes(self) -> None:
        """A grant is a narrowing gate, not a way around the base pairing scope."""
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://carol:8766", adapter=_ReversibleAdapter())
        hello = self.bob.hello(carol.id_card())
        # Paired with only "observe." -- no "reversible." prefix at all.
        self.bob.confirm_peer(carol.identity.system_id, hello["pair_code"], ["observe."])
        grant = self.bob.issue_grant(carol.identity.system_id, ["reversible."], timedelta(minutes=5))
        envelope = carol.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "draft-2", "idempotency_key": "draft-2", "capability": "reversible.workspace.draft.v1",
            "risk": "reversible", "grant": {"id": grant["grant_id"]},
        })
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(envelope)
        self.assertEqual(raised.exception.code, "auth.not_authorized")


if __name__ == "__main__":
    unittest.main()
