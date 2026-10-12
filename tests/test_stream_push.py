"""Live stream forwarding requires consent from the source and recipient."""

from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.crypto.envelope import verify
from fasp_harness.policy.sharing import StreamSharingPolicy
from fasp_harness.streaming import packetize
from fasp_harness.timestamps import now, stamp


class StreamFixture:
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.carol = FaspHarness(root / "carol", "carol", "http://carol:8766")
        sharing = StreamSharingPolicy.from_config([
            {
                "capability": "observe.stream.v1",
                "peer_ids": [self.alice.identity.system_id],
                "purposes": ["telemetry"],
                "fields": ["sample"],
                "content_types": ["application/octet-stream"],
                "delivery_modes": ["reliable"],
                "max_rate_hz": 10000,
                "max_duration_s": 300,
                "max_payload_bytes": 8,
                "max_window": 4,
                "max_retention_packets": 4,
                "forward_to": [self.carol.identity.system_id],
            }
        ])
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766", stream_sharing=sharing)
        for peer in (self.alice, self.carol):
            hello = self.bob.hello(peer.id_card())
            self.bob.confirm_peer(peer.identity.system_id, hello["pair_code"])
        self.alice_grant = self._grant(self.alice)
        self.carol_grant = self._grant(self.carol)

    def tearDown(self) -> None:
        self.alice.close()
        self.bob.close()
        self.carol.close()
        self.temp.cleanup()

    def _grant(self, peer: FaspHarness) -> dict[str, Any]:
        return self.bob.issue_grant(peer.identity.system_id, ["observe.stream.v1"], timedelta(minutes=5), purpose="telemetry")

    def _grant_ref(self, peer: FaspHarness) -> dict[str, str]:
        grant = self.alice_grant if peer is self.alice else self.carol_grant
        return {"id": grant["grant_id"], "digest": grant["digest"]}

    def _open_stream(self) -> str:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, {
            "capability": "observe.stream.v1",
            "purpose": "telemetry",
            "fields": ["sample"],
            "recipient": self.bob.identity.system_id,
            "content_type": "application/octet-stream",
            "delivery": "reliable",
            "max_rate_hz": 10000,
            "duration_s": 60,
            "expires_at": stamp(now() + timedelta(seconds=60)),
            "max_payload_bytes": 8,
            "window": 4,
            "retention_packets": 4,
            "forward_to": [self.carol.identity.system_id],
            "grant": self._grant_ref(self.alice),
        }))
        return opened["stream_id"]

    def _subscribe(self, peer: FaspHarness, stream_id: str) -> dict[str, Any]:
        return peer.make_envelope("stream.subscribe", self.bob.identity.system_id, {
            "capability": "observe.stream.v1",
            "stream_id": stream_id,
            "grant": self._grant_ref(peer),
        })

    def _send_packet(self, stream_id: str, sequence: int, data: bytes = b"x") -> dict[str, Any]:
        packet = next(packetize(stream_id, 0, sequence, data, "application/octet-stream", 8))
        packet["capability"] = "observe.stream.v1"
        return self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))


class StreamPushWiringTests(StreamFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.pushes: list[tuple[str, dict[str, Any]]] = []
        self.bob.channels.push = lambda peer_id, message: self.pushes.append((peer_id, message)) or True

    def test_owner_cannot_subscribe_to_its_own_stream(self) -> None:
        stream_id = self._open_stream()
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_subscribe(self._subscribe(self.alice, stream_id))
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_only_source_named_and_locally_allowed_recipient_can_subscribe(self) -> None:
        stream_id = self._open_stream()
        subscribe = self.bob.stream_subscribe(self._subscribe(self.carol, stream_id))
        self.assertEqual(subscribe["type"], "stream.subscribed")

        dave = FaspHarness(Path(self.temp.name) / "dave", "dave", "http://dave:8766")
        self.addCleanup(dave.close)
        hello = self.bob.hello(dave.id_card())
        self.bob.confirm_peer(dave.identity.system_id, hello["pair_code"])
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_subscribe(self._subscribe(dave, stream_id))
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_forwarded_push_is_signed_by_the_authorizing_node(self) -> None:
        stream_id = self._open_stream()
        self.bob.stream_subscribe(self._subscribe(self.carol, stream_id))
        self._send_packet(stream_id, 0)

        self.assertEqual(len(self.pushes), 1)
        peer_id, message = self.pushes[0]
        self.assertEqual(peer_id, self.carol.identity.system_id)
        self.assertEqual(message["type"], "stream.push")
        self.assertEqual(message["packet"]["sequence"], 0)
        self.assertEqual(message["origin_peer"], self.alice.identity.system_id)
        self.assertEqual(message["recipient_peer"], self.carol.identity.system_id)
        verify(message, self.bob.identity.public_b64)

        self._send_packet(stream_id, 0)
        self.assertEqual(len(self.pushes), 1, "a duplicate packet must not be forwarded twice")

    def test_unsubscribe_stops_future_pushes(self) -> None:
        stream_id = self._open_stream()
        self.bob.stream_subscribe(self._subscribe(self.carol, stream_id))
        self._send_packet(stream_id, 0)
        self.assertEqual(len(self.pushes), 1)

        unsubscribe = self.carol.make_envelope("stream.unsubscribe", self.bob.identity.system_id, {"stream_id": stream_id})
        self.bob.stream_unsubscribe(unsubscribe)
        self._send_packet(stream_id, 1)
        self.assertEqual(len(self.pushes), 1)

    def test_revoked_recipient_grant_stops_live_pushes(self) -> None:
        stream_id = self._open_stream()
        self.bob.stream_subscribe(self._subscribe(self.carol, stream_id))
        self._send_packet(stream_id, 0)
        self.bob.revoke_grant(self.carol_grant["grant_id"])

        self._send_packet(stream_id, 1)

        self.assertEqual(len(self.pushes), 1)
        self.assertEqual(self.bob.streams.subscribers_of(stream_id), set())

    def test_revoked_recipient_peer_stops_live_pushes(self) -> None:
        stream_id = self._open_stream()
        self.bob.stream_subscribe(self._subscribe(self.carol, stream_id))
        self._send_packet(stream_id, 0)
        self.bob.revoke_peer(self.carol.identity.system_id, "test revocation")

        self._send_packet(stream_id, 1)

        self.assertEqual(len(self.pushes), 1)
        self.assertEqual(self.bob.streams.subscribers_of(stream_id), set())

    def test_closing_a_stream_clears_its_subscribers(self) -> None:
        stream_id = self._open_stream()
        self.bob.stream_subscribe(self._subscribe(self.carol, stream_id))
        self.assertEqual(self.bob.streams.subscribers_of(stream_id), {self.carol.identity.system_id})

        close = self.alice.make_envelope("stream.close", self.bob.identity.system_id, {"capability": "observe.stream.v1", "stream_id": stream_id})
        self.bob.stream_close(close)
        self.assertEqual(self.bob.streams.subscribers_of(stream_id), set())


if __name__ == "__main__":
    unittest.main()
