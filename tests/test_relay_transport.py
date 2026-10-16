"""Encrypted, authenticated mailbox delivery over a three-hop relay chain."""

from __future__ import annotations

import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fasp_harness.core import FaspHarness
from fasp_harness.protocol.errors import FaspError
from fasp_harness.timestamps import now, stamp
from fasp_harness.transport.relay_client import RelayClient
from fasp_harness.transport.relay_hub import RelayHub


class RelayTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://127.0.0.1:8101")
        self.bob = FaspHarness(root / "bob", "bob", "http://127.0.0.1:8102")
        self.addCleanup(self.alice.close)
        self.addCleanup(self.bob.close)
        for local, remote in ((self.alice, self.bob), (self.bob, self.alice)):
            hello = local.hello(remote.id_card())
            local.confirm_peer(remote.identity.system_id, hello["pair_code"])
        self.hubs = {name: RelayHub(root / name) for name in ("hub-a", "hub-b", "hub-c")}
        for hub in self.hubs.values():
            self.addCleanup(hub.close)

        def token(hub: str, account: str, role: str) -> Path:
            path = root / f"{hub}-{account}.token"
            path.write_text(self.hubs[hub].authorize(account, role=role), encoding="utf-8")
            return path

        alice_id, bob_id = self.alice.identity.system_id, self.bob.identity.system_id
        RelayClient.configure(self.alice.state.directory, "http://127.0.0.1:8101", token("hub-a", alice_id, "client"))
        RelayClient.configure(self.bob.state.directory, "http://127.0.0.1:8103", token("hub-c", bob_id, "client"))
        self.hubs["hub-a"].set_route(bob_id, "http://127.0.0.1:8102", "a-forward", token("hub-b", "a-forward", "relay"))
        self.hubs["hub-b"].set_route(bob_id, "http://127.0.0.1:8103", "b-forward", token("hub-c", "b-forward", "relay"))
        self.hubs["hub-c"].set_route(alice_id, "http://127.0.0.1:8102", "c-forward", token("hub-b", "c-forward", "relay"))
        self.hubs["hub-b"].set_route(alice_id, "http://127.0.0.1:8101", "b-return", token("hub-a", "b-return", "relay"))
        self.urls = {"http://127.0.0.1:8101": self.hubs["hub-a"], "http://127.0.0.1:8102": self.hubs["hub-b"], "http://127.0.0.1:8103": self.hubs["hub-c"]}

    def network(self, origin, account, token, method, path, payload=None, **kwargs):
        del kwargs
        hub = self.urls[origin]
        role = hub.authenticate(account, token)
        if method == "GET":
            return {"frames": hub.poll(account)}
        if path.endswith("/ack"):
            if role != "client":
                raise FaspError("auth.relay_denied", "Only clients may acknowledge.")
            hub.ack(account, payload["id"])
            return {"ok": True}
        return hub.accept(payload["frame"], payload["path"], actor=account, role=role)

    def test_end_to_end_request_and_reply_across_three_hubs(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {"idempotency_key": "relay-1", "capability": "coordinate.chat.v1", "objective": "private instruction"})
        with patch("fasp_harness.transport.relay_client.relay_http", side_effect=self.network), patch("fasp_harness.transport.relay_hub.relay_http", side_effect=self.network):
            alice = RelayClient(self.alice, timeout=3.0)
            bob = RelayClient(self.bob, timeout=3.0)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(alice.send_request, self.bob.identity.system_id, envelope)
                for _ in range(100):
                    frames = self.hubs["hub-c"].poll(self.bob.identity.system_id)
                    if frames:
                        break
                    if future.done():
                        future.result()
                    time.sleep(0.01)
                self.assertEqual(len(frames), 1)
                self.assertNotIn("private instruction", str(frames[0]["frame"]))
                self.assertEqual(bob.process_once()["replied"], 1)
                reply = future.result(timeout=3)
            heartbeat = self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(alice.send_request, self.bob.identity.system_id, heartbeat)
                for _ in range(100):
                    if self.hubs["hub-c"].poll(self.bob.identity.system_id):
                        break
                    time.sleep(0.01)
                self.assertEqual(bob.process_once()["replied"], 1)
                pong = future.result(timeout=3)
        self.assertEqual(reply["type"], "receipt.delivered")
        self.assertEqual(reply["response"]["output"]["summary"], "private instruction")
        self.assertEqual(pong["type"], "heartbeat")
        self.assertEqual(self.hubs["hub-a"].poll(self.alice.identity.system_id), [])

    def test_tampering_and_unprovisioned_sender_fail_closed(self) -> None:
        card = self.bob.id_card()
        frame = self.alice.relay_key.seal(self.alice.identity, self.bob.identity.system_id, card["relay_public_key"], "message-1", "request", {"text": "secret"}, stamp(now() + timedelta(seconds=90)))
        altered = dict(frame)
        altered["ciphertext"] = frame["ciphertext"][:-1] + ("A" if frame["ciphertext"][-1] != "A" else "B")
        with self.assertRaises(FaspError):
            self.bob.relay_key.open(altered, self.alice.id_card(), self.bob.identity.system_id)
        with self.assertRaises(FaspError):
            self.hubs["hub-a"].authenticate(self.alice.identity.system_id, "wrong-token")
        with self.assertRaises(FaspError):
            self.hubs["hub-a"].accept(frame, [], actor="some-other-node", role="client")
        with self.assertRaises(FaspError):
            self.hubs["hub-b"].accept(frame, [self.hubs["hub-b"].hub_id], actor="relay-hop", role="relay")

    def test_failed_reply_keeps_request_for_safe_deduplicated_retry(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {"idempotency_key": "retry-1", "capability": "coordinate.chat.v1", "objective": "once"})
        card = self.bob.id_card()
        frame = self.alice.relay_key.seal(self.alice.identity, self.bob.identity.system_id, card["relay_public_key"], envelope["message_id"], "request", {"envelope": envelope}, envelope["expires_at"])

        def network_with_failed_reply(origin, account, token, method, path, payload=None, **kwargs):
            if payload and payload.get("frame", {}).get("kind") == "response":
                raise FaspError("transport.unreachable", "next hub offline")
            return self.network(origin, account, token, method, path, payload, **kwargs)

        with patch("fasp_harness.transport.relay_client.relay_http", side_effect=network_with_failed_reply), patch("fasp_harness.transport.relay_hub.relay_http", side_effect=network_with_failed_reply):
            alice = RelayClient(self.alice)
            alice._call("POST", "/relay/v1/messages", {"frame": frame, "path": []})
            with self.assertRaises(FaspError):
                RelayClient(self.bob).process_once()
        self.assertEqual(len(self.hubs["hub-c"].poll(self.bob.identity.system_id)), 1)
        self.assertEqual(self.bob.tasks.get("retry-1")["state"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()
