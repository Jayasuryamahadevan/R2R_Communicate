"""Onboarding and network-adapter tests; no actual sockets needed."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness
from fasp_harness.plugplay import _check_url, connect, paired_peer, peer_summary, send


class FakeHTTP:
    def __init__(self, remote: FaspHarness):
        self.remote = remote

    def json(self, url: str, payload=None, *, allow_insecure=False):
        del allow_insecure
        if url.endswith("/profile"):
            return self.remote.id_card()
        if url.endswith("/pair/hello"):
            return self.remote.hello(payload["id_card"])
        if url.endswith("/fasp/v1/envelopes"):
            _, response = self.remote.accept(payload)
            if payload["kind"] == "intent.propose":
                return {"type": "receipt.delivered", "response": response}
            return response
        raise AssertionError(f"Unexpected route: {url}")


class ReversibleAdapter(DefaultSafeAdapter):
    def capabilities(self):
        return [{"id": "coordinate.change.v1", "risk": "reversible", "max_runtime_s": 5, "network": "none"}]

    def handle(self, intent):
        return {"changed": True}


class PlugPlayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.alice = FaspHarness(root / "a", "alice", "https://a.example")
        self.bob = FaspHarness(root / "b", "bob", "https://b.example")
        self.http = FakeHTTP(self.bob)

    def tearDown(self):
        self.alice.close()
        self.bob.close()
        self.tmp.cleanup()

    def test_pairing_requires_both_local_approvals_then_task_works(self):
        info = connect(self.alice, "https://b.example", http=self.http)
        self.assertEqual(info["peer_id"], self.bob.identity.system_id)
        self.assertEqual(info["pair_code"], self.alice.peers.get(self.bob.identity.system_id)["pair_code"])
        self.assertEqual(peer_summary(self.alice)[0]["state"], "pending")
        with self.assertRaises(FaspError):
            paired_peer(self.alice, "bob")

        self.alice.confirm_peer(self.bob.identity.system_id, info["pair_code"])
        self.bob.confirm_peer(self.alice.identity.system_id, info["pair_code"])
        result = send(
            self.alice, "bob", "intent.propose",
            {"idempotency_key": "one", "capability": "observe.system.status.v1", "objective": "Status"},
            http=self.http,
        )
        self.assertEqual(result["type"], "task.result")
        self.assertEqual(result["status"], "completed")
        again = send(
            self.alice, "bob", "task.status", {"idempotency_key": "one"}, http=self.http,
        )
        self.assertEqual(again["type"], "task.result")

    def test_insecure_remote_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, "disabled"):
            _check_url("http://192.168.1.2:8766", allow_insecure=False)
        self.assertEqual(_check_url("http://127.0.0.1:8766", False), "http://127.0.0.1:8766")
        self.assertEqual(_check_url("http://192.168.1.2:8766", True), "http://192.168.1.2:8766")

    def test_identity_and_pairing_are_required_for_send(self):
        with self.assertRaises(ValueError):
            send(self.alice, "bob", "heartbeat", {}, http=self.http)

    def test_remote_cannot_downgrade_local_reversible_capability(self):
        remote = FaspHarness(Path(self.tmp.name) / "reversible", "reversible", "https://reversible.example", adapter=ReversibleAdapter())
        try:
            hello = remote.hello(self.alice.id_card())
            remote.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
            payload = {
                "idempotency_key": "downgrade-attempt",
                "capability": "coordinate.change.v1",
                "objective": "Change state",
                "risk": "observe",
            }
            with self.assertRaises(FaspError) as ctx:
                remote.accept(self.alice.make_envelope("intent.propose", remote.identity.system_id, payload))
            self.assertEqual(ctx.exception.code, "policy.risk_mismatch")
        finally:
            remote.close()


if __name__ == "__main__":
    unittest.main()
