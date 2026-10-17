"""Large task results become content-addressed artifacts (FASP_PROTOCOL.md ss11)
instead of being inlined past a signed envelope's 64 KiB cap (ss5)."""

from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any

from fasp_harness.core import ARTIFACT_INLINE_THRESHOLD_BYTES, DefaultSafeAdapter, FaspError, FaspHarness
from fasp_harness.timestamps import now, stamp


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

    def test_foreign_peer_cannot_fetch_artifact_even_when_paired(self) -> None:
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://carol:8766")
        hello = self.bob.hello(carol.id_card())
        self.bob.confirm_peer(carol.identity.system_id, hello["pair_code"])
        try:
            artifact = self.bob.artifacts.put(b"private", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:00.000Z")
            request = carol.make_envelope("artifact.fetch", self.bob.identity.system_id, {"artifact_id": artifact["artifact_id"]})
            with self.assertRaises(FaspError) as raised:
                self.bob.accept(request)
            self.assertEqual(raised.exception.code, "auth.not_authorized")
        finally:
            carol.close()

    def test_identical_bytes_allow_distinct_authorized_owners(self) -> None:
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://carol:8766")
        try:
            first = self.bob.artifacts.put(b"same bytes", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:00.000Z")
            second = self.bob.artifacts.put(b"same bytes", "application/octet-stream", carol.identity.system_id, "2026-01-01T00:00:01.000Z")
            self.assertEqual(first["artifact_id"], second["artifact_id"])
            self.assertTrue(self.bob.artifacts.can_fetch(first["artifact_id"], self.alice.identity.system_id))
            self.assertTrue(self.bob.artifacts.can_fetch(first["artifact_id"], carol.identity.system_id))
        finally:
            carol.close()

    def test_modified_bytes_fail_integrity_check(self) -> None:
        artifact = self.bob.artifacts.put(b"original", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:00.000Z")
        Path(artifact["storage_path"]).write_bytes(b"tampered")
        with self.assertRaises(FaspError) as raised:
            self.bob.artifacts.read_bytes(artifact["artifact_id"])
        self.assertEqual(raised.exception.code, "storage.artifact_corrupt")

    def test_storing_identical_bytes_twice_deduplicates_by_digest(self) -> None:
        first = self.bob.artifacts.put(b"same bytes", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:00.000Z")
        second = self.bob.artifacts.put(b"same bytes", "application/octet-stream", self.alice.identity.system_id, "2026-01-01T00:00:01.000Z")
        self.assertEqual(first["artifact_id"], second["artifact_id"])

    def test_expired_retention_is_reclaimed_before_the_size_cap_bites(self) -> None:
        """`retention_until` is enforced, not just recorded: otherwise the
        store fills with expired bytes and every later put fails forever."""
        store = self.bob.artifacts
        store.max_total_bytes = 64
        expired = store.put(b"A" * 48, "application/octet-stream", self.alice.identity.system_id, stamp(now()), retention=timedelta(seconds=-1))
        fresh = store.put(b"B" * 48, "application/octet-stream", self.alice.identity.system_id, stamp(now()), retention=timedelta(days=1))
        self.assertIsNone(store.get(expired["artifact_id"]))
        self.assertFalse(Path(expired["storage_path"]).exists())
        self.assertEqual(store.total_bytes(), 48)
        self.assertIsNotNone(store.get(fresh["artifact_id"]))

        # An artifact with no retention date is never reclaimed for age.
        keep = store.put(b"C" * 8, "application/octet-stream", self.alice.identity.system_id, stamp(now()))
        self.assertEqual(store.purge_expired(), 0)
        self.assertIsNotNone(store.get(keep["artifact_id"]))

    def test_concurrent_identical_puts_do_not_race_the_unique_digest(self) -> None:
        store = self.bob.artifacts
        pool = 8
        barrier = threading.Barrier(pool)
        results: list[dict[str, Any]] = []
        failures: list[BaseException] = []

        def store_same_bytes() -> None:
            barrier.wait()
            try:
                results.append(store.put(b"identical", "application/octet-stream", self.alice.identity.system_id, stamp(now())))
            except BaseException as exc:  # noqa: BLE001 - collected for the assertion below
                failures.append(exc)

        threads = [threading.Thread(target=store_same_bytes) for _ in range(pool)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(len(results), pool)
        self.assertEqual({result["artifact_id"] for result in results}, {results[0]["artifact_id"]})
        self.assertEqual(store.total_bytes(), len(b"identical"))


if __name__ == "__main__":
    unittest.main()
