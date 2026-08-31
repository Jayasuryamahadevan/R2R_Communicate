"""End-to-end tests of the Starlette/uvicorn ASGI transport (transport/http_app.py),
using Starlette's TestClient rather than a live socket."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from fasp_harness.core import FaspHarness
from fasp_harness.transport.http_app import create_app


class TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        self.client = TestClient(create_app(self.bob))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_health_and_profile(self) -> None:
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json()["ok"])

        profile = self.client.get("/profile")
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.json()["system_id"], self.bob.identity.system_id)

        alias = self.client.get("/.well-known/fasp/id-card.json")
        self.assertEqual(alias.status_code, 200)
        self.assertEqual(alias.json()["system_id"], self.bob.identity.system_id)

    def test_peers_requires_admin_token(self) -> None:
        unauthenticated = self.client.get("/peers")
        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(unauthenticated.json()["error"]["code"], "auth.admin_required")

        wrong_token = self.client.get("/peers", headers={"X-FASP-Admin-Token": "wrong"})
        self.assertEqual(wrong_token.status_code, 401)

        authenticated = self.client.get("/peers", headers={"X-FASP-Admin-Token": self.bob.admin_token})
        self.assertEqual(authenticated.status_code, 200)
        self.assertEqual(authenticated.json(), {})

    def test_full_pairing_and_envelope_round_trip_over_http(self) -> None:
        hello = self.client.post("/pair/hello", json={"id_card": self.alice.id_card()})
        self.assertEqual(hello.status_code, 200)
        pair_code = hello.json()["pair_code"]

        confirm = self.client.post(
            "/pair/confirm",
            json={"peer_id": self.alice.identity.system_id, "pair_code": pair_code},
            headers={"X-FASP-Admin-Token": self.bob.admin_token},
        )
        self.assertEqual(confirm.status_code, 200)
        self.assertTrue(confirm.json()["ok"])

        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "http-1", "idempotency_key": "http-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        posted = self.client.post("/fasp/v1/envelopes", json=envelope)
        self.assertEqual(posted.status_code, 200)
        body = posted.json()
        self.assertEqual(body["type"], "receipt.delivered")
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["response"]["status"], "completed")

    def test_unknown_envelope_kind_is_rejected(self) -> None:
        hello = self.client.post("/pair/hello", json={"id_card": self.alice.id_card()})
        self.client.post(
            "/pair/confirm",
            json={"peer_id": self.alice.identity.system_id, "pair_code": hello.json()["pair_code"]},
            headers={"X-FASP-Admin-Token": self.bob.admin_token},
        )
        envelope = self.alice.make_envelope("session.hello", self.bob.identity.system_id, {})
        posted = self.client.post("/fasp/v1/envelopes", json=envelope)
        self.assertEqual(posted.status_code, 404)
        self.assertEqual(posted.json()["error"]["code"], "protocol.unsupported_kind")

    def test_oversized_body_is_rejected(self) -> None:
        posted = self.client.post("/fasp/v1/envelopes", content=b"x" * (70 * 1024), headers={"Content-Type": "application/json"})
        self.assertEqual(posted.status_code, 400)
        self.assertEqual(posted.json()["error"]["code"], "schema.invalid")


if __name__ == "__main__":
    unittest.main()
