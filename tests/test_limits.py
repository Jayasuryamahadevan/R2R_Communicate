"""Conformance #8 (FASP_PROTOCOL.md ss15): enforce message, rate, and
artifact storage limits."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from fasp_harness.core import FaspError, FaspHarness


class LimitsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _paired(self, **bob_kwargs: Any) -> tuple[FaspHarness, FaspHarness]:
        alice = FaspHarness(self.root / "alice", "alice", "http://alice:8766")
        bob = FaspHarness(self.root / "bob", "bob", "http://bob:8766", **bob_kwargs)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
        return alice, bob

    def test_oversized_inline_envelope_is_rejected(self) -> None:
        alice, bob = self._paired()
        envelope = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "big", "idempotency_key": "big", "capability": "observe.system.status.v1", "risk": "observe",
            "padding": "x" * 100_000,
        })
        with self.assertRaises(FaspError) as raised:
            bob.accept(envelope)
        self.assertEqual(raised.exception.code, "resource.too_large")

    def test_peer_exceeding_its_rate_limit_is_rejected(self) -> None:
        # A near-zero refill rate keeps the test deterministic: only the
        # fixed burst of 2 tokens is available for the whole test.
        alice, bob = self._paired(rate_limit_per_second=0.001, rate_limit_burst=2)
        for index in range(2):
            envelope = alice.make_envelope("intent.propose", bob.identity.system_id, {
                "intent_id": f"rl-{index}", "idempotency_key": f"rl-{index}", "capability": "observe.system.status.v1", "risk": "observe",
            })
            bob.accept(envelope)  # consumes the 2-token burst

        third = alice.make_envelope("intent.propose", bob.identity.system_id, {
            "intent_id": "rl-2", "idempotency_key": "rl-2", "capability": "observe.system.status.v1", "risk": "observe",
        })
        with self.assertRaises(FaspError) as raised:
            bob.accept(third)
        self.assertEqual(raised.exception.code, "resource.exhausted")

    def test_artifact_store_rejects_once_the_total_size_cap_is_reached(self) -> None:
        alice, bob = self._paired()
        bob.artifacts.max_total_bytes = 10
        with self.assertRaises(FaspError) as raised:
            bob.artifacts.put(b"more than ten bytes of data", "application/octet-stream", alice.identity.system_id, "2026-01-01T00:00:00.000Z")
        self.assertEqual(raised.exception.code, "resource.exhausted")


if __name__ == "__main__":
    unittest.main()
