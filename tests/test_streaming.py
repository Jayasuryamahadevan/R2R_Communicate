from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.streaming import Reassembler, packetize


class StreamingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_reliable_stream_acknowledges_and_reassembles(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, {
            "capability": "observe.stream.v1", "content_type": "application/octet-stream", "delivery": "reliable", "max_payload_bytes": 8, "window": 4, "retention_packets": 4,
        }))
        packet = next(packetize(opened["stream_id"], 0, 0, b"hello", "application/octet-stream", 8))
        packet["capability"] = "observe.stream.v1"
        acknowledged = self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertEqual(acknowledged["ack_sequence"], 0)
        self.assertEqual(Reassembler().add(packet), b"hello")
        duplicate = self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertTrue(duplicate["duplicate"])

    def test_reliable_stream_rejects_gap(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, {
            "capability": "observe.stream.v1", "content_type": "application/json", "delivery": "reliable", "max_payload_bytes": 32, "window": 2,
        }))
        packet = next(packetize(opened["stream_id"], 0, 1, b"{}", "application/json", 32))
        packet["capability"] = "observe.stream.v1"
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertEqual(raised.exception.code, "stream.out_of_order")


if __name__ == "__main__":
    unittest.main()
