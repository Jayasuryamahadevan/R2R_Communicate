from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.policy.sharing import StreamSharingPolicy
from fasp_harness.streaming import Reassembler, packetize
from fasp_harness.timestamps import now, stamp


class StreamingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(
            root / "bob",
            "bob",
            "http://bob:8766",
            stream_sharing=StreamSharingPolicy.from_config([
                {
                    "capability": "observe.stream.v1",
                    "peer_ids": [self.alice.identity.system_id],
                    "purposes": ["telemetry"],
                    "fields": ["temperature_c"],
                    "content_types": ["application/octet-stream", "application/json"],
                    "delivery_modes": ["reliable", "latest"],
                    "max_rate_hz": 10000,
                    "max_duration_s": 300,
                    "max_payload_bytes": 40 * 1024,
                    "max_window": 32,
                    "max_retention_packets": 32,
                    "forward_to": [],
                }
            ]),
        )
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        self.grant = self.bob.issue_grant(
            self.alice.identity.system_id,
            ["observe.stream.v1"],
            timedelta(minutes=5),
            purpose="telemetry",
        )

    def _open_payload(self, content_type: str, max_payload_bytes: int, window: int) -> dict[str, object]:
        return {
            "capability": "observe.stream.v1",
            "purpose": "telemetry",
            "fields": ["temperature_c"],
            "recipient": self.bob.identity.system_id,
            "content_type": content_type,
            "delivery": "reliable",
            "max_rate_hz": 100,
            "duration_s": 60,
            "expires_at": stamp(now() + timedelta(seconds=60)),
            "max_payload_bytes": max_payload_bytes,
            "window": window,
            "retention_packets": 4,
            "forward_to": [],
            "grant": {"id": self.grant["grant_id"], "digest": self.grant["digest"]},
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_reliable_stream_acknowledges_and_reassembles(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, self._open_payload("application/octet-stream", 8, 4)))
        packet = next(packetize(opened["stream_id"], 0, 0, b"hello", "application/octet-stream", 8))
        packet["capability"] = "observe.stream.v1"
        acknowledged = self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertEqual(acknowledged["ack_sequence"], 0)
        self.assertEqual(Reassembler().add(packet), b"hello")
        duplicate = self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertTrue(duplicate["duplicate"])

    def test_a_packet_losing_the_race_with_close_is_refused_not_retained(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, self._open_payload("application/octet-stream", 8, 4)))
        packet = next(packetize(opened["stream_id"], 0, 0, b"hello", "application/octet-stream", 8))
        packet["capability"] = "observe.stream.v1"
        repo = self.bob.streams.repo
        real_advance = repo.advance

        def advance_after_a_concurrent_close(*args: object, **kwargs: object) -> bool:
            # The close thread committed after the packet was validated but
            # before its sequence state was written.
            repo.close(opened["stream_id"], "closed concurrently")
            return real_advance(*args, **kwargs)

        repo.advance = advance_after_a_concurrent_close  # type: ignore[method-assign]
        try:
            with self.assertRaises(FaspError) as raised:
                self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        finally:
            repo.advance = real_advance  # type: ignore[method-assign]
        self.assertEqual(raised.exception.code, "stream.not_open")
        self.assertEqual(repo.get(opened["stream_id"])["next_expected"], 0)
        self.assertEqual(repo.packets_after(opened["stream_id"], -1), [])

    def test_closing_a_stream_releases_its_retained_packets(self) -> None:
        payload = self._open_payload("application/octet-stream", 8, 4)
        payload["max_rate_hz"] = 10_000
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload))
        for sequence in range(2):
            packet = next(packetize(opened["stream_id"], 0, sequence, f"p{sequence}".encode(), "application/octet-stream", 8))
            packet["capability"] = "observe.stream.v1"
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        repo = self.bob.streams.repo
        self.assertEqual(len(repo.packets_after(opened["stream_id"], -1)), 2)

        repo.close(opened["stream_id"], "done")
        self.assertEqual(repo.packets_after(opened["stream_id"], -1), [])

    def test_a_naive_expires_at_is_refused_with_a_clean_schema_error(self) -> None:
        """`datetime.fromisoformat` accepts "2030-01-01"; comparing that naive
        deadline with an aware `now()` raises a bare TypeError. A paired peer
        sending it must get a schema refusal (and nothing opened), not a 500
        with the inbox row left unanswered."""
        payload = self._open_payload("application/json", 32, 2)
        payload["expires_at"] = "2030-01-01"
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload))
        self.assertEqual(raised.exception.code, "schema.invalid")
        self.assertEqual(self.bob.db.read("SELECT COUNT(*) AS n FROM streams")[0]["n"], 0)

    def test_reliable_stream_rejects_gap(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, self._open_payload("application/json", 32, 2)))
        packet = next(packetize(opened["stream_id"], 0, 1, b"{}", "application/json", 32))
        packet["capability"] = "observe.stream.v1"
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertEqual(raised.exception.code, "stream.out_of_order")

    def test_stream_sequence_rejects_boolean_values(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, self._open_payload("application/json", 32, 2)))
        packet = next(packetize(opened["stream_id"], 0, 0, b"{}", "application/json", 32))
        packet["capability"] = "observe.stream.v1"
        packet["sequence"] = True
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet))
        self.assertEqual(raised.exception.code, "stream.invalid_sequence")

    def test_stream_enforces_its_accepted_packet_rate(self) -> None:
        payload = self._open_payload("application/octet-stream", 8, 4)
        payload["max_rate_hz"] = 0.01
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload))
        first = next(packetize(opened["stream_id"], 0, 0, b"one", "application/octet-stream", 8))
        first["capability"] = "observe.stream.v1"
        self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, first))

        second = next(packetize(opened["stream_id"], 0, 1, b"two", "application/octet-stream", 8))
        second["capability"] = "observe.stream.v1"
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, second))
        self.assertEqual(raised.exception.code, "stream.rate_exceeded")

    def test_expired_stream_is_closed_before_pull(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, self._open_payload("application/json", 32, 2)))
        with self.bob.db.write() as conn:
            conn.execute(
                "UPDATE streams SET expires_at = ? WHERE stream_id = ?",
                (stamp(now() - timedelta(seconds=1)), opened["stream_id"]),
            )
        pull = self.alice.make_envelope("stream.pull", self.bob.identity.system_id, {
            "capability": "observe.stream.v1",
            "stream_id": opened["stream_id"],
            "after_sequence": -1,
        })
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_pull(pull)
        self.assertEqual(raised.exception.code, "lease.expired")
        self.assertEqual(self.bob.streams.repo.get(opened["stream_id"])["state"], "closed")

    def test_stream_is_denied_without_a_local_sharing_rule(self) -> None:
        policy = self.bob.stream_sharing
        self.bob.stream_sharing = StreamSharingPolicy()
        try:
            payload = self._open_payload("application/json", 32, 2)
            with self.assertRaises(FaspError) as raised:
                self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload))
            self.assertEqual(raised.exception.code, "auth.not_authorized")
        finally:
            self.bob.stream_sharing = policy

    def test_stream_rejects_fields_outside_local_allowlist(self) -> None:
        payload = self._open_payload("application/json", 32, 2)
        payload["fields"] = ["temperature_c", "raw_audio"]
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload))
        self.assertEqual(raised.exception.code, "auth.not_authorized")

    def test_json_packet_enforces_declared_top_level_fields(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope(
            "stream.open", self.bob.identity.system_id, self._open_payload("application/json", 128, 2),
        ))
        allowed = next(packetize(opened["stream_id"], 0, 0, b'{"temperature_c":21.5}', "application/json", 128))
        allowed["capability"] = "observe.stream.v1"
        ack = self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, allowed))
        self.assertEqual(ack["ack_sequence"], 0)

        next_opened = self.bob.stream_open(self.alice.make_envelope(
            "stream.open", self.bob.identity.system_id, self._open_payload("application/json", 128, 2),
        ))
        undeclared = next(packetize(
            next_opened["stream_id"], 0, 0,
            b'{"temperature_c":21.5,"raw_audio":"private"}',
            "application/json", 128,
        ))
        undeclared["capability"] = "observe.stream.v1"
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, undeclared))
        self.assertEqual(raised.exception.code, "auth.not_authorized")
        self.assertEqual(self.bob.streams.repo.get(next_opened["stream_id"])["last_sequence"], -1)

    def test_json_packet_must_be_one_complete_record(self) -> None:
        opened = self.bob.stream_open(self.alice.make_envelope(
            "stream.open", self.bob.identity.system_id, self._open_payload("application/json", 8, 4),
        ))
        record = b'{"temperature_c":21.5}'
        with self.assertRaises(ValueError):
            list(packetize(opened["stream_id"], 0, 0, record, "application/json", 8))
        fragments = list(packetize(
            opened["stream_id"], 0, 0, record, "application/octet-stream", 8,
        ))
        fragments[0]["content_type"] = "application/json"
        fragments[0]["capability"] = "observe.stream.v1"
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_packet(self.alice.make_envelope("stream.packet", self.bob.identity.system_id, fragments[0]))
        self.assertEqual(raised.exception.code, "stream.invalid_json")

    def test_grant_can_narrow_the_local_stream_rate_limit(self) -> None:
        grant = self.bob.issue_grant(
            self.alice.identity.system_id,
            ["observe.stream.v1"],
            timedelta(minutes=5),
            purpose="telemetry",
            constraints={"max_rate_hz": 1},
        )
        payload = self._open_payload("application/json", 32, 2)
        payload["max_rate_hz"] = 2
        payload["grant"] = {"id": grant["grant_id"], "digest": grant["digest"]}
        with self.assertRaises(FaspError) as raised:
            self.bob.stream_open(self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload))
        self.assertEqual(raised.exception.code, "auth.not_authorized")


if __name__ == "__main__":
    unittest.main()
