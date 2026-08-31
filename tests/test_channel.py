"""Phase 11 conformance: the `/fasp/v1/channel` websocket -- the same
signed-envelope protocol as `/fasp/v1/envelopes`, just carried over a
persistent full-duplex connection, plus proactive push delivery of a
task result to a peer's live channel."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from fasp_harness.core import DefaultSafeAdapter, FaspHarness
from fasp_harness.transport.http_app import create_app


class _BlockingAdapter(DefaultSafeAdapter):
    """Returns only after being told to, from a background thread, so a
    test can observe the push arriving strictly after the websocket
    request that triggered it already got its own (queued) reply."""

    def __init__(self) -> None:
        self._ready = threading.Event()

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        self._ready.wait(timeout=5)
        return super().handle(intent)

    def release(self) -> None:
        self._ready.set()


class WebsocketChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        # The lifespan context (where `channels.bind_loop` runs) only fires
        # when TestClient is used as a context manager -- a plain
        # `TestClient(app)` never triggers ASGI startup/shutdown at all.
        self._client_ctx = TestClient(create_app(self.bob))
        self.client = self._client_ctx.__enter__()

    def tearDown(self) -> None:
        self._client_ctx.__exit__(None, None, None)
        self.alice.close()
        self.bob.close()
        self.temp.cleanup()

    def test_envelope_round_trip_over_the_websocket_matches_http(self) -> None:
        envelope = self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})
        with self.client.websocket_connect("/fasp/v1/channel") as socket:
            socket.send_json(envelope)
            response = socket.receive_json()
        self.assertEqual(response["type"], "heartbeat")

    def test_malformed_frame_gets_a_protocol_error_without_closing_the_socket(self) -> None:
        with self.client.websocket_connect("/fasp/v1/channel") as socket:
            socket.send_json({"not": "an envelope"})
            error_response = socket.receive_json()
            self.assertEqual(error_response["error"]["code"], "schema.invalid")

            envelope = self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})
            socket.send_json(envelope)
            ok_response = socket.receive_json()
            self.assertEqual(ok_response["type"], "heartbeat")

    def test_completed_task_result_is_pushed_to_a_connected_peers_channel(self) -> None:
        adapter = _BlockingAdapter()
        self._client_ctx.__exit__(None, None, None)
        self.bob.close()
        self.bob = FaspHarness(Path(self.temp.name) / "bob2", "bob", "http://bob2:8766", adapter=adapter)
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        adapter.capabilities = lambda: [{"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 0.05, "network": "none"}]
        self._client_ctx = TestClient(create_app(self.bob))
        client = self._client_ctx.__enter__()

        with client.websocket_connect("/fasp/v1/channel") as socket:
            # The near-zero max_runtime_s forces the synchronous propose to
            # time out (returning task.progress) so the eventual COMPLETED
            # outcome is only observable through the push below.
            propose = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
                "intent_id": "push-1", "idempotency_key": "push-1", "capability": "observe.system.status.v1", "risk": "observe",
            })
            socket.send_json(propose)
            queued = socket.receive_json()
            self.assertEqual(queued["response"]["status"], "running")

            time.sleep(0.1)
            adapter.release()
            pushed = socket.receive_json()
            self.assertEqual(pushed["type"], "task.push")
            self.assertEqual(pushed["response"]["status"], "completed")
            self.assertEqual(pushed["response"]["idempotency_key"], "push-1")


if __name__ == "__main__":
    unittest.main()
