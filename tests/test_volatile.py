"""Explicit loss semantics, no packet journaling, bounded replay and live authority."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fasp_harness.core import FaspError, FaspHarness, now, stamp
from fasp_harness.crypto.envelope import sign, verify
from fasp_harness.policy.sharing import StreamSharingPolicy
from fasp_harness.protocol.contracts import check_peer_features
from fasp_harness.protocol.volatile import VOLATILE_FEATURE, VolatileInbox
from fasp_harness.streaming import packetize


class VolatileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.alice = FaspHarness(self.root / "alice", "alice", "http://alice")
        self.policy = StreamSharingPolicy.from_config([{
            "capability": "observe.stream.v1", "peer_ids": [self.alice.identity.system_id],
            "purposes": ["telemetry"], "fields": ["sample"], "content_types": ["application/octet-stream"],
            "delivery_modes": ["latest", "reliable"], "storage_modes": ["disk", "memory"],
            "max_rate_hz": 10000, "max_duration_s": 60, "max_payload_bytes": 1024,
            "max_window": 4, "max_retention_packets": 4, "forward_to": [],
        }])
        self.bob = self.node()
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        self.grant = self.bob.issue_grant(self.alice.identity.system_id, ["observe.stream.v1"], timedelta(minutes=1), purpose="telemetry")

    def node(self) -> FaspHarness:
        return FaspHarness(self.root / "bob", "bob", "http://bob", stream_sharing=self.policy, rate_limit_burst=1000)

    def tearDown(self) -> None:
        self.alice.close()
        self.bob.close()
        self.temp.cleanup()

    def envelope(self, kind: str = "heartbeat", payload: dict | None = None) -> dict:
        return self.alice.make_envelope(kind, self.bob.identity.system_id, payload or {}, delivery="volatile", receiver_instance=self.bob.instance_id)

    def resign(self, envelope: dict) -> dict:
        return sign(envelope, self.alice.identity.private, self.alice.identity.kid)

    def open_stream(self, **changes) -> str:
        payload = {
            "capability": "observe.stream.v1", "purpose": "telemetry", "fields": ["sample"],
            "recipient": self.bob.identity.system_id, "content_type": "application/octet-stream",
            "delivery": "latest", "storage": "memory", "max_rate_hz": 10000, "duration_s": 60,
            "expires_at": stamp(now() + timedelta(seconds=60)), "max_payload_bytes": 1024,
            "window": 4, "retention_packets": 0, "forward_to": [],
            "grant": {"id": self.grant["grant_id"], "digest": self.grant["digest"]},
        }
        payload.update(changes)
        envelope = self.alice.make_envelope("stream.open", self.bob.identity.system_id, payload)
        envelope["required_features"] = [VOLATILE_FEATURE]
        return self.bob.stream_open(self.resign(envelope))["stream_id"]

    def packet(self, stream_id: str, sequence: int = 0) -> dict:
        packet = next(packetize(stream_id, 0, sequence, b"temperature", "application/octet-stream", 1024))
        packet["capability"] = "observe.stream.v1"
        return self.envelope("stream.packet", packet)

    def test_volatile_heartbeat_does_not_write_sqlite_and_deduplicates(self) -> None:
        envelope = self.envelope()
        changes = self.bob.db.connection.total_changes
        duplicate, result = self.bob.accept(envelope)
        self.assertFalse(duplicate)
        self.assertEqual(result["type"], "heartbeat")
        self.assertEqual(self.bob.accept(envelope), (True, result))
        self.assertEqual(self.bob.db.connection.total_changes, changes)

    def test_memory_packet_sequence_is_live_only_without_packet_or_inbox_writes(self) -> None:
        stream_id = self.open_stream()
        envelope = self.packet(stream_id)
        changes = self.bob.db.connection.total_changes
        _, ack = self.bob.accept(envelope)
        self.assertEqual(ack["ack_sequence"], 0)
        ack["ack_sequence"] = 999  # Caller mutations cannot corrupt replay state.
        duplicate, cached = self.bob.accept(envelope)
        self.assertTrue(duplicate)
        self.assertEqual(cached["ack_sequence"], 0)
        self.assertEqual(self.bob.db.connection.total_changes, changes)
        self.assertEqual(self.bob.streams.repo.get(stream_id)["last_sequence"], -1)
        self.assertEqual(self.bob.streams.repo.packets_after(stream_id, -1), [])
        self.assertIsNone(self.bob.inbox.get_response(envelope["message_id"]))

    def test_durable_default_heartbeat_is_still_persisted_and_replayable(self) -> None:
        envelope = self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})
        _, result = self.bob.accept(envelope)
        self.assertEqual(self.bob.inbox.get_response(envelope["message_id"]), result)
        self.assertEqual(self.bob.accept(envelope), (True, result))

    def test_volatile_control_work_is_refused_before_effect(self) -> None:
        envelope = self.envelope("intent.propose", {"idempotency_key": "unsafe", "capability": "observe.system.status.v1"})
        with self.assertRaises(FaspError) as error:
            self.bob.accept(envelope)
        self.assertEqual(error.exception.code, "protocol.unsupported_delivery")
        self.assertIsNone(self.bob.tasks.get("unsafe"))

    def test_explicit_feature_instance_and_short_lifetime_are_required(self) -> None:
        for field, value, code in (
            ("required_features", [], "protocol.unsupported_delivery"),
            ("receiver_instance", "other-process", "auth.wrong_instance"),
            ("expires_at", stamp(now() + timedelta(seconds=10)), "schema.invalid"),
            ("delivery", "unknown", "schema.invalid"),
        ):
            envelope = self.envelope()
            envelope[field] = value
            with self.assertRaises(FaspError) as error:
                self.bob.accept(self.resign(envelope))
            self.assertEqual(error.exception.code, code)

    def test_replay_cannot_survive_receiver_restart(self) -> None:
        envelope = self.envelope()
        self.bob.accept(envelope)
        old_instance = self.bob.instance_id
        self.bob.close()
        self.bob = self.node()
        self.assertNotEqual(self.bob.instance_id, old_instance)
        with self.assertRaises(FaspError) as error:
            self.bob.accept(envelope)
        self.assertEqual(error.exception.code, "auth.wrong_instance")

    def test_memory_stream_cannot_resume_a_sequence_after_receiver_restart(self) -> None:
        stream_id = self.open_stream()
        self.bob.accept(self.packet(stream_id))
        self.bob.close()
        self.bob = self.node()
        with self.assertRaises(FaspError) as error:
            self.bob.accept(self.packet(stream_id, 1))
        self.assertEqual(error.exception.code, "stream.session_expired")

    def test_same_message_id_with_changed_signed_content_is_rejected(self) -> None:
        envelope = self.envelope()
        self.bob.accept(envelope)
        envelope["payload"] = {"changed": True}
        with self.assertRaises(FaspError) as error:
            self.bob.accept(self.resign(envelope))
        self.assertEqual(error.exception.code, "auth.replay_conflict")

    def test_revocation_and_scope_changes_are_checked_on_every_request(self) -> None:
        self.bob.accept(self.envelope())
        self.bob.revoke_peer(self.alice.identity.system_id, "test")
        with self.assertRaises(FaspError) as error:
            self.bob.accept(self.envelope())
        self.assertEqual(error.exception.code, "auth.peer_revoked")

    def test_revoked_stream_grant_is_not_hidden_by_key_or_contract_caching(self) -> None:
        stream_id = self.open_stream()
        self.bob.accept(self.packet(stream_id))
        self.bob.revoke_grant(self.grant["grant_id"])
        with self.assertRaises(FaspError) as error:
            self.bob.accept(self.packet(stream_id, 1))
        self.assertEqual(error.exception.code, "auth.grant_expired")

    def test_memory_stream_needs_policy_permission_latest_and_no_retention(self) -> None:
        for changes in ({"delivery": "reliable"}, {"retention_packets": 1}):
            with self.assertRaises(FaspError):
                self.open_stream(**changes)
        self.bob.streams.max_memory_streams = 1
        self.open_stream()
        with self.assertRaises(FaspError) as error:
            self.open_stream()
        self.assertEqual(error.exception.code, "resource.exhausted")

    def test_durable_packet_cannot_silently_persist_a_memory_stream(self) -> None:
        stream_id = self.open_stream()
        packet = self.packet(stream_id)["payload"]
        envelope = self.alice.make_envelope("stream.packet", self.bob.identity.system_id, packet)
        with self.assertRaises(FaspError) as error:
            self.bob.accept(envelope)
        self.assertEqual(error.exception.code, "protocol.unsupported_delivery")

    def test_live_forwarding_is_signed_once_and_stops_after_recipient_revocation(self) -> None:
        carol = FaspHarness(self.root / "carol", "carol", "http://carol")
        self.addCleanup(carol.close)
        peer_id = carol.identity.system_id
        hello = self.bob.hello(carol.id_card())
        self.bob.confirm_peer(peer_id, hello["pair_code"])
        self.bob.stream_sharing = StreamSharingPolicy([replace(self.policy.rules[0], forward_to=frozenset({peer_id}))])
        grant = self.bob.issue_grant(peer_id, ["observe.stream.v1"], timedelta(minutes=1), purpose="telemetry")
        stream_id = self.open_stream(forward_to=[peer_id])
        self.bob.stream_subscribe(carol.make_envelope("stream.subscribe", self.bob.identity.system_id, {
            "stream_id": stream_id, "capability": "observe.stream.v1", "grant": {"id": grant["grant_id"], "digest": grant["digest"]},
        }))
        pushes = []
        self.bob.channels.push = lambda recipient, message: pushes.append((recipient, message)) or True
        packet = self.packet(stream_id)
        self.bob.accept(packet)
        self.bob.accept(packet)
        self.assertEqual(len(pushes), 1)
        self.assertEqual(pushes[0][0], peer_id)
        self.assertEqual(pushes[0][1]["storage"], "memory")
        self.assertEqual(pushes[0][1]["expires_at"], packet["expires_at"])
        verify(pushes[0][1], self.bob.identity.public_b64)
        self.bob.revoke_peer(peer_id, "recipient consent removed")
        self.bob.accept(self.packet(stream_id, 1))
        self.assertEqual(len(pushes), 1)


class VolatileCapacityTests(unittest.TestCase):
    def test_sender_refuses_legacy_peers_before_relying_on_volatile_semantics(self) -> None:
        check_peer_features({}, [])
        for card in ({}, {"protocol_support": {"features": [VOLATILE_FEATURE]}}, {"protocol_support": {"features": 1}}):
            with self.assertRaises(FaspError):
                check_peer_features(card, [VOLATILE_FEATURE])
        check_peer_features({"protocol_support": {"features": ["fasp.required-features.v1", VOLATILE_FEATURE]}}, [VOLATILE_FEATURE])

    def test_unexpired_entries_are_not_evicted_and_expired_slots_are_reclaimed(self) -> None:
        inbox = VolatileInbox(2)
        calls = []

        def handle() -> dict:
            calls.append(True)
            return {"type": "heartbeat"}

        with patch("fasp_harness.protocol.volatile.time.time", return_value=100):
            inbox.accept("one", b"one", 101, handle)
            inbox.accept("two", b"two", 102, handle)
            with self.assertRaises(FaspError):
                inbox.accept("three", b"three", 102, handle)
            self.assertTrue(inbox.accept("one", b"one", 101, handle)[0])
            self.assertEqual(len(calls), 2)
        with patch("fasp_harness.protocol.volatile.time.time", return_value=101.5):
            self.assertFalse(inbox.accept("three", b"three", 103, handle)[0])
            self.assertEqual(len(inbox._entries), 2)
            self.assertEqual(len(inbox._expiry), 2)
