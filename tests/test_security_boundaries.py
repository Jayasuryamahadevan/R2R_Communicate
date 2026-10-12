"""Security regression tests for untrusted peer input and durable identities."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness
from fasp_harness.crypto.envelope import sign
from fasp_harness.crypto.identity import Identity


class _GrantRequiredAdapter(DefaultSafeAdapter):
    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            *super().capabilities(),
            {"id": "reversible.workspace.draft.v1", "risk": "reversible", "max_runtime_s": 5, "network": "none"},
        ]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        if intent.get("capability") == "reversible.workspace.draft.v1":
            return {"draft": "private result"}
        return super().handle(intent)


class SecurityBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.adapter = _GrantRequiredAdapter()
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766", adapter=self.adapter)
        self.carol = FaspHarness(root / "carol", "carol", "http://carol:8766")
        for member in (self.alice, self.carol):
            hello = self.bob.hello(member.id_card())
            self.bob.confirm_peer(member.identity.system_id, hello["pair_code"], ["observe.", "reversible."])

    def tearDown(self) -> None:
        for member in (self.alice, self.bob, self.carol):
            member.close()
        self.temp.cleanup()

    def _request(self, member: FaspHarness, key: str, **updates: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "intent_id": key,
            "idempotency_key": key,
            "capability": "observe.system.status.v1",
            "risk": "observe",
        }
        payload.update(updates)
        return member.make_envelope("intent.propose", self.bob.identity.system_id, payload)

    def test_untrusted_caller_cannot_downgrade_adapter_risk(self) -> None:
        request = self._request(
            self.alice, "downgrade", capability="reversible.workspace.draft.v1", risk="observe",
        )
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(request)
        self.assertEqual(raised.exception.code, "policy.requires_confirmation")
        self.assertEqual(self.adapter.calls, 0)

    def test_declared_reversible_risk_still_requires_a_grant(self) -> None:
        request = self._request(
            self.alice, "no-grant", capability="reversible.workspace.draft.v1", risk="reversible",
        )
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(request)
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        self.assertEqual(self.adapter.calls, 0)

    def test_foreign_peer_cannot_read_results_by_reusing_intent_key(self) -> None:
        _, original = self.bob.accept(self._request(self.alice, "owned-by-alice"))
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._request(self.carol, "owned-by-alice"))
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        _, replayed = self.bob.accept(self._request(self.alice, "owned-by-alice"))
        self.assertEqual(replayed, original)

    def test_same_peer_must_not_change_request_under_same_intent_key(self) -> None:
        self.bob.accept(self._request(self.alice, "immutable"))
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(self._request(self.alice, "immutable", objective="different action"))
        self.assertEqual(raised.exception.code, "schema.idempotency_conflict")

    def test_message_id_collision_across_peers_is_not_a_response_oracle(self) -> None:
        original = self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})
        self.bob.accept(original)
        conflicting = self.carol.make_envelope("heartbeat", self.bob.identity.system_id, {})
        conflicting["message_id"] = original["message_id"]
        conflicting = sign(conflicting, self.carol.identity.private, self.carol.identity.kid)
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(conflicting)
        self.assertEqual(raised.exception.code, "auth.replay_conflict")

    def test_message_id_collision_with_changed_content_is_rejected(self) -> None:
        original = self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})
        self.bob.accept(original)
        conflicting = dict(original)
        conflicting["payload"] = {"different": True}
        conflicting = sign(conflicting, self.alice.identity.private, self.alice.identity.kid)
        with self.assertRaises(FaspError) as raised:
            self.bob.accept(conflicting)
        self.assertEqual(raised.exception.code, "auth.replay_conflict")


class PrivateFilePermissionsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_identity_and_admin_token_remain_private_with_permissive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_umask = os.umask(0)
            try:
                harness = FaspHarness(root / "node", "node", "http://127.0.0.1:8766")
                try:
                    for filename in ("identity.json", "admin_token"):
                        mode = stat.S_IMODE((root / "node" / filename).stat().st_mode)
                        self.assertEqual(mode, 0o600, filename)
                finally:
                    harness.close()
            finally:
                os.umask(old_umask)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_new_identity_file_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "identity.json"
            old_umask = os.umask(0)
            try:
                Identity.load_or_create(key_path)
            finally:
                os.umask(old_umask)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
