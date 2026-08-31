"""Large task results become content-addressed artifacts (FASP_PROTOCOL.md ss11)
instead of being inlined past a signed envelope's 64 KiB cap (ss5)."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import ARTIFACT_INLINE_THRESHOLD_BYTES, DefaultSafeAdapter, FaspHarness


class _LargeOutputAdapter(DefaultSafeAdapter):
    def capabilities(self) -> list[dict[str, Any]]:
        return [*super().capabilities(), {"id": "observe.bulk.v1", "risk": "observe", "max_runtime_s": 5, "network": "none"}]

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        if intent.get("capability") == "observe.bulk.v1":
            return {"status": "ok", "blob": "x" * (ARTIFACT_INLINE_THRESHOLD_BYTES * 2)}
        return super().handle(intent)


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.alice = FaspHarness(root / "alice", "alice", "http://alice:8766")
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766", adapter=_LargeOutputAdapter())
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_large_output_is_stored_as_an_artifact_reference(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "bulk-1", "idempotency_key": "bulk-1", "capability": "observe.bulk.v1", "risk": "observe",
        })
        _, response = self.bob.accept(envelope)
        self.assertEqual(response["status"], "completed")
        self.assertNotIn("output", response)
        self.assertIn("artifact", response)
        self.assertTrue(response["artifact"]["artifact_id"].startswith("artifact-"))

    def test_small_output_stays_inline(self) -> None:
        envelope = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "small-1", "idempotency_key": "small-1", "capability": "observe.system.status.v1", "risk": "observe",
        })
        _, response = self.bob.accept(envelope)
        self.assertIn("output", response)
        self.assertNotIn("artifact", response)

    def test_artifact_fetch_round_trips_the_original_bytes(self) -> None:
        propose = self.alice.make_envelope("intent.propose", self.bob.identity.system_id, {
            "intent_id": "bulk-2", "idempotency_key": "bulk-2", "capability": "observe.bulk.v1", "risk": "observe",
        })
        _, response = self.bob.accept(propose)
        artifact_id = response["artifact"]["artifact_id"]

        fetch = self.alice.make_envelope("artifact.fetch", self.bob.identity.system_id, {"artifact_id": artifact_id})
        _, fetched = self.bob.accept(fetch)
        self.assertEqual(fetched["digest"], response["artifact"]["digest"])

        raw = base64.urlsafe_b64decode(fetched["payload"] + "=" * (-len(fetched["payload"]) % 4))
        self.assertEqual(json.loads(raw)["blob"], "x" * (ARTIFACT_INLINE_THRESHOLD_BYTES * 2))

    def test_storing_identical_bytes_twice_deduplicates_by_digest(self) -> None:
        first = self.bob.artifacts.put(b"same bytes", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:00.000Z")
        second = self.bob.artifacts.put(b"same bytes", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:01.000Z")
        self.assertEqual(first["artifact_id"], second["artifact_id"])


if __name__ == "__main__":
    unittest.main()
