"""Live-stream push delivery (FASP_MESSAGING_STREAMING.md's streaming
profile): `stream.subscribe` opts a peer in to real-time delivery of a
stream's future packets over its open channel, on top of the existing
durable `stream.pull` backstop."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.streaming import packetize
from fasp_harness.transport.http_app import create_app


class StreamPushWiringTests(unittest.TestCase):
    """Verifies core.py wires subscriber fan-out correctly, without
    needing a real event loop: channels.push is monkeypatched to record
    calls instead of actually scheduling a coroutine."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        self.carol = FaspHarness(root / "carol", "carol", "http://carol:8766")
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        hello = self.bob.hello(self.carol.id_card())
        self.bob.confirm_peer(self.carol.identity.system_id, hello["pair_code"])
        self.pushes: list[tuple[str, dict[str, Any]]] = []
        self.bob.channels.push = lambda peer_id, message: self.pushes.append((peer_id, message)) or True

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _open_stream(self) -> str:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, {
            "capability": "observe.stream.v1", "content_type": "application/octet-stream", "delivery": "reliable", "max_payload_bytes": 8, "window": 4, "retention_packets": 4,
        }))
        return opened["stream_id"]

    def _send_packet(self, stream_id: str, sequence: int, data: bytes = b"x") -> dict[str, Any]:
        packet = next(packetize(stream_id, 0, sequence, data, "application/octet-stream", 8))
        packet["capability"] = "observe.stream.v1"
        return self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))

    def test_owner_cannot_subscribe_to_its_own_stream(self) -> None:
        stream_id = self._open_stream()
        subscribe = self.alice.make_envelope("stream.subscribe", self.bob.identity.system_id, {"capability": "observe.stream.v1", "stream_id": stream_id})
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_subscribe(subscribe)
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_subscriber_receives_a_push_for_a_new_packet_but_not_a_duplicate(self) -> None:
        stream_id = self._open_stream()
        subscribe = self.carol.make_envelope("stream.subscribe", self.bob.identity.system_id, {"capability": "observe.stream.v1", "stream_id": stream_id})
        subscribed = self.bob.stream_subscribe(subscribe)
        self.assertEqual(subscribed["type"], "stream.subscribed")

        self._send_packet(stream_id, 0)
        self.assertEqual(len(self.pushes), 1)
        peer_id, message = self.pushes[0]
        self.assertEqual(peer_id, self.carol.identity.system_id)
        self.assertEqual(message["type"], "stream.push")
        self.assertEqual(message["packet"]["sequence"], 0)

        # A retransmit of the same sequence is "duplicate" -- no second push.
        self._send_packet(stream_id, 0)
        self.assertEqual(len(self.pushes), 1)

    def test_unsubscribe_stops_future_pushes(self) -> None:
        stream_id = self._open_stream()
        subscribe = self.carol.make_envelope("stream.subscribe", self.bob.identity.system_id, {"capability": "observe.stream.v1", "stream_id": stream_id})
        self.bob.stream_subscribe(subscribe)
        self._send_packet(stream_id, 0)
        self.assertEqual(len(self.pushes), 1)

        unsubscribe = self.carol.make_envelope("stream.unsubscribe", self.bob.identity.system_id, {"stream_id": stream_id})
        self.bob.stream_unsubscribe(unsubscribe)
        self._send_packet(stream_id, 1)
        self.assertEqual(len(self.pushes), 1)

    def test_closing_a_stream_clears_its_subscribers(self) -> None:
        stream_id = self._open_stream()
        subscribe = self.carol.make_envelope("stream.subscribe", self.bob.identity.system_id, {"capability": "observe.stream.v1", "stream_id": stream_id})
        self.bob.stream_subscribe(subscribe)
        self.assertEqual(self.bob.streams.subscribers_of(stream_id), {self.carol.identity.system_id})

        close = self.alice.make_envelope("stream.close", self.bob.identity.system_id, {"stream_id": stream_id})
        self.bob.stream_close(close)
        self.assertEqual(self.bob.streams.subscribers_of(stream_id), set())


class StreamPushLiveTests(unittest.TestCase):
    """End-to-end: a subscriber connected over the real websocket channel
    receives a `stream.push` frame the moment another peer's packet (sent
    over plain HTTP) is accepted -- proving live delivery is genuinely
    cross-transport, not tied to how the sender happened to connect."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        self.carol = FaspHarness(root / "carol", "carol", "http://carol:8766")
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        hello = self.bob.hello(self.carol.id_card())
        self.bob.confirm_peer(self.carol.identity.system_id, hello["pair_code"])
        self._client_ctx = TestClient(create_app(self.bob))
        self.client = self._client_ctx.__enter__()

    def tearDown(self) -> None:
        self._client_ctx.__exit__(None, None, None)
        self.alice.close()
        self.bob.close()
        self.temp.cleanup()

    def test_subscribed_peer_gets_a_live_push_over_its_websocket(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, {
            "capability": "observe.stream.v1", "content_type": "application/octet-stream", "delivery": "reliable", "max_payload_bytes": 8, "window": 4, "retention_packets": 4,
        }))
        stream_id = opened["stream_id"]

        with self.client.websocket_connect("/fasp/v1/channel") as socket:
            subscribe = self.carol.make_envelope("stream.subscribe", self.bob.identity.system_id, {"capability": "observe.stream.v1", "stream_id": stream_id})
            socket.send_json(subscribe)
            subscribed = socket.receive_json()
            self.assertEqual(subscribed["type"], "stream.subscribed")

            packet = next(packetize(stream_id, 0, 0, b"telemetry", "application/octet-stream", 8))
            packet["capability"] = "observe.stream.v1"
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))

            pushed = socket.receive_json()
            self.assertEqual(pushed["type"], "stream.push")
            self.assertEqual(pushed["stream_id"], stream_id)
            self.assertEqual(pushed["packet"]["sequence"], 0)


if __name__ == "__main__":
    unittest.main()
