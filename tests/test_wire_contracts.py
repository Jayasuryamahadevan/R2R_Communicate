"""Adversarial ingress tests, including the public transport boundary."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator, FormatChecker
from starlette.testclient import TestClient

from fasp_harness.core import FaspError, FaspHarness, now, stamp
from fasp_harness.crypto.canonical import canonicalize
from fasp_harness.crypto.envelope import sign, unb64, verify
from fasp_harness.protocol.contracts import MAX_JSON_DEPTH
from fasp_harness.protocol.schemas import definitions, wire_schema
from fasp_harness.transport.canonical import decode_object
from fasp_harness.transport.http_app import create_app
from fasp_harness.transport.openapi import schema


class WireContractsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob", rate_limit_burst=1000)
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])
        self.client = TestClient(create_app(self.bob))

    def tearDown(self) -> None:
        self.alice.close()
        self.bob.close()
        self.temp.cleanup()

    def envelope(self) -> dict:
        return self.alice.make_envelope("heartbeat", self.bob.identity.system_id, {})

    def resign(self, record: dict) -> dict:
        return sign(record, self.alice.identity.private, self.alice.identity.kid)

    def test_malformed_envelope_fields_return_errors_without_journaling(self) -> None:
        for name, value in (
            ("signature", []), ("signature", None), ("signature", {"alg": "Ed25519", "value": "AA"}),
            ("from", {}), ("to", []), ("kind", {}), ("message_id", []), ("nonce", 1),
            ("issued_at", "2026-01-01T00:00:00"), ("expires_at", {}),
            ("payload", []), ("conversation_id", {}), ("causation_id", []),
        ):
            with self.subTest(name=name, value=value):
                envelope = self.envelope()
                envelope[name] = value
                response = self.client.post("/fasp/v1/envelopes", json=envelope)
                self.assertIn(response.status_code, (400, 401))
                self.assertEqual(response.json()["type"], "protocol.error")
        self.assertEqual(self.bob.db.read_one("SELECT COUNT(*) AS n FROM envelopes_inbox")["n"], 0)

    def test_malformed_cards_do_not_create_pending_peers(self) -> None:
        for value in (None, [], 1, "card"):
            self.assertEqual(self.client.post("/pair/hello", json={"id_card": value}).status_code, 400)
        for name, value in (("signature", []), ("expires_at", "not-a-time"), ("endpoints", []), ("display_name", {}), ("public_key", {})):
            card = self.alice.id_card()
            card[name] = value
            self.assertIn(self.client.post("/pair/hello", json={"id_card": card}).status_code, (400, 401))
        self.assertEqual(len(self.bob.peers.all()), 1)

    def test_temporal_order_and_future_card_are_rejected(self) -> None:
        record = self.envelope()
        record["issued_at"] = stamp(now() + timedelta(seconds=10))
        record["expires_at"] = stamp(now() + timedelta(seconds=5))
        self.assertEqual(self.client.post("/fasp/v1/envelopes", json=self.resign(record)).status_code, 400)
        card = self.alice.id_card()
        card["issued_at"] = stamp(now() + timedelta(hours=1))
        self.assertEqual(self.client.post("/pair/hello", json={"id_card": self.resign(card)}).status_code, 401)

    def test_version_and_required_features_fail_closed(self) -> None:
        for field, value, code in (
            ("fasp", "fasp/99.0", "protocol.unsupported_version"),
            ("required_features", ["vendor.unknown.v1"], "protocol.unsupported_feature"),
            ("required_features", [1], "schema.invalid"),
            ("required_features", ["same", "same"], "schema.invalid"),
        ):
            envelope = self.envelope()
            envelope[field] = value
            result = self.client.post("/fasp/v1/envelopes", json=self.resign(envelope))
            self.assertEqual(result.status_code, 400)
            self.assertEqual(result.json()["error"]["code"], code)

    def test_optional_extensions_are_covered_by_signature(self) -> None:
        envelope = self.envelope()
        envelope["vendor.example"] = {"units": "m/s", "value": 0.125}
        envelope["required_features"] = ["fasp.required-features.v1"]
        envelope = self.resign(envelope)
        self.assertEqual(self.client.post("/fasp/v1/envelopes", json=envelope).status_code, 200)
        envelope["vendor.example"]["value"] = 100
        self.assertEqual(self.client.post("/fasp/v1/envelopes", json=envelope).status_code, 401)

    def test_signature_encoding_and_key_identifier_are_strict(self) -> None:
        for suffix in ("=", "!", " "):
            envelope = self.envelope()
            envelope["signature"]["value"] += suffix
            self.assertEqual(self.client.post("/fasp/v1/envelopes", json=envelope).status_code, 401)
        envelope = self.envelope()
        envelope["signature"]["kid"] = "another-key"
        self.assertEqual(self.client.post("/fasp/v1/envelopes", json=envelope).status_code, 401)
        for value in ("AB", "A", "AA==", "+/", "AA\n"):
            with self.assertRaises(ValueError):
                unb64(value)

    def test_signed_key_id_cannot_be_changed_or_downgraded_in_discovery(self) -> None:
        card = self.alice.id_card()
        card["signature"]["kid"] = "forged-selector"
        self.assertEqual(self.client.post("/pair/hello", json={"id_card": card}).status_code, 401)
        card = self.alice.id_card()
        del card["key_id"]
        response = self.client.post("/pair/hello", json={"id_card": self.resign(card)})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.bob.peers.get(self.alice.identity.system_id)["card"]["key_id"], self.alice.identity.kid)

    def test_legacy_client_card_with_null_endpoints_remains_valid(self) -> None:
        card = self.alice.id_card()
        for name in ("key_id", "protocol_support", "issued_at"):
            del card[name]
        card["endpoints"] = {"profile": None, "envelopes": None}
        FaspHarness.verify_id_card(self.resign(card))

    def test_invalid_unicode_and_depth_are_rejected_on_all_ingress_paths(self) -> None:
        with self.assertRaises(FaspError) as error:
            decode_object(b'{"bad":"\\ud800"}')
        self.assertEqual(error.exception.code, "schema.invalid")
        deep: dict = {}
        for _ in range(MAX_JSON_DEPTH + 1):
            deep = {"next": deep}
        with self.assertRaises(FaspError) as error:
            decode_object(json.dumps(deep).encode())
        self.assertEqual(error.exception.code, "resource.too_large")
        envelope = self.envelope()
        envelope["payload"] = deep
        with self.assertRaises(FaspError):
            self.bob.accept(envelope)
        with self.client.websocket_connect("/fasp/v1/channel") as socket:
            socket.send_text('{"bad":"\\ud800"}')
            self.assertEqual(socket.receive_json()["error"]["code"], "schema.invalid")

    def test_binary_websocket_frame_is_closed_without_server_exception(self) -> None:
        with self.client.websocket_connect("/fasp/v1/channel") as socket:
            socket.send_bytes(b"binary")
            self.assertEqual(socket.receive(), {"type": "websocket.close", "code": 1003, "reason": ""})

    def test_operator_input_is_validated_before_coercion_or_sql(self) -> None:
        headers = {"X-FASP-Admin-Token": self.bob.admin_token}
        for path, payload in (
            ("/pair/confirm", {"peer_id": {}, "pair_code": []}),
            ("/pair/confirm", {"peer_id": "id", "pair_code": "code", "allowed_capability_prefixes": "observe."}),
            ("/pair/revoke", {"peer_id": [], "reason": {}}),
            ("/grants/revoke", {"grant_id": {}}),
            ("/grants/issue", {"subject_peer": "id", "capability_prefixes": [], "duration_seconds": "forever"}),
            ("/grants/issue", {"subject_peer": "id", "capability_prefixes": [], "duration_seconds": True}),
            ("/grants/issue", {"subject_peer": "id", "capability_prefixes": [], "duration_seconds": 2**53 - 1}),
        ):
            with self.subTest(path=path, payload=payload):
                self.assertEqual(self.client.post(path, json=payload, headers=headers).status_code, 400)

    def test_typed_payload_fields_cannot_crash_dispatch(self) -> None:
        for kind, payload in (
            ("inbox.pull", {"cursor": {}}), ("stream.pull", {"after_sequence": []}),
            ("intent.propose", {"idempotency_key": "x", "capability": "observe.system.status.v1", "intent_id": []}),
        ):
            envelope = self.alice.make_envelope(kind, self.bob.identity.system_id, payload)
            self.assertEqual(self.client.post("/fasp/v1/envelopes", json=envelope).status_code, 400)

    def test_cached_rejection_keeps_its_http_status_on_replay(self) -> None:
        envelope = self.alice.make_envelope("artifact.fetch", self.bob.identity.system_id, {"artifact_id": "not-owned"})
        first = self.client.post("/fasp/v1/envelopes", json=envelope)
        second = self.client.post("/fasp/v1/envelopes", json=envelope)
        self.assertEqual(first.status_code, 401)
        self.assertEqual(second.status_code, first.status_code)
        self.assertEqual(second.json(), first.json())

    def test_schemas_match_live_profiles_and_are_not_duplicated_in_openapi(self) -> None:
        contract = wire_schema()
        Draft202012Validator.check_schema(contract)
        validator = Draft202012Validator(contract, format_checker=FormatChecker())
        validator.validate(self.alice.id_card())
        validator.validate(self.envelope())
        self.assertEqual(self.client.get("/schemas/fasp-wire-v1.json").json(), contract)
        self.assertEqual(json.loads((Path(__file__).parents[1] / "spec/fasp-wire-v1.schema.json").read_text()), contract)
        for name, definition in definitions().items():
            self.assertEqual(schema()["components"]["schemas"][name], definition)
        support = self.bob.id_card()["protocol_support"]
        self.assertEqual(support["accepted_kinds"], sorted(self.bob.DISPATCH))
        self.assertEqual(support["identity_encoding"], "sha256-base64url-no-padding")

    @given(st.sampled_from(["signature", "payload", "from", "to", "kind", "message_id", "issued_at", "expires_at", "nonce"]), st.one_of(st.none(), st.integers(), st.lists(st.integers(), max_size=3), st.dictionaries(st.text(max_size=3), st.booleans(), max_size=3)))
    @settings(max_examples=60, deadline=None)
    def test_arbitrary_field_type_mutations_only_raise_protocol_errors(self, field: str, value: object) -> None:
        envelope = copy.deepcopy(self.envelope())
        assume(value != envelope[field])
        envelope[field] = value
        with self.assertRaises(FaspError):
            self.bob.accept(envelope)

    def test_verify_rejects_nonobject_signature(self) -> None:
        for signature in (None, [], "invalid", 0):
            envelope = self.envelope()
            envelope["signature"] = signature
            with self.assertRaises(FaspError):
                verify(envelope, self.alice.identity.public_b64)

    def test_reused_canonical_bytes_preserve_the_exact_wire_size_limit(self) -> None:
        envelope = self.envelope()
        envelope["payload"] = {"padding": ""}
        envelope = self.resign(envelope)
        padding = 65536 - len(canonicalize(envelope))
        envelope["payload"]["padding"] = "x" * padding
        envelope = self.resign(envelope)
        self.assertEqual(len(canonicalize(envelope)), 65536)
        self.assertEqual(self.bob.accept(envelope)[1]["type"], "heartbeat")
        envelope["payload"]["padding"] += "x"
        with self.assertRaises(FaspError) as error:
            self.bob.accept(self.resign(envelope))
        self.assertEqual(error.exception.code, "resource.too_large")
