"""safety.halt/safety.status/incident.report/heartbeat (FASP_PROTOCOL.md ss9, ss11).

A network peer may only ever REQUEST a halt, never clear one -- clearing
is local-only (LocalSafetyGate.clear_halt(), never called from a
network-facing handler)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.robotics import LocalSafetyGate


class SafetyMessageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _paired(self, safety_gate: LocalSafetyGate | None = None) -> tuple[FaspHarness, FaspHarness]:
        alice = FaspHarness(self.root / "alice", "alice", "http://alice:8766")
        bob = FaspHarness(self.root / "bob", "bob", "http://bob:8766", safety_gate=safety_gate)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
        return alice, bob

    def test_safety_halt_requires_a_configured_gate(self) -> None:
        alice, bob = self._paired(safety_gate=None)
        envelope = alice.make_envelope("safety.halt", bob.identity.system_id, {"reason": "test"})
        with self.assertRaises(FaspError) as raised:
            bob.safety_halt(envelope)
        self.assertEqual(raised.exception.code, "capability.unavailable")

    def test_network_halt_request_blocks_local_validation_until_locally_cleared(self) -> None:
        gate = LocalSafetyGate(maximum_speed_mps=2.0)
        alice, bob = self._paired(safety_gate=gate)

        # Local preconditions are otherwise all healthy.
        gate.validate(1.0, estop_clear=True, obstacle_clear=True, localization_healthy=True, reservation_active=True)

        envelope = alice.make_envelope("safety.halt", bob.identity.system_id, {"reason": "operator requested stop"})
        response = bob.safety_halt(envelope)
        self.assertTrue(response["halt_requested"])

        with self.assertRaises(FaspError) as raised:
            gate.validate(1.0, estop_clear=True, obstacle_clear=True, localization_healthy=True, reservation_active=True)
        self.assertEqual(raised.exception.code, "safety.estop_active")

        # Only local code can clear it -- there is no network-facing method for this.
        gate.clear_halt()
        gate.validate(1.0, estop_clear=True, obstacle_clear=True, localization_healthy=True, reservation_active=True)

    def test_safety_status_reports_the_gate(self) -> None:
        gate = LocalSafetyGate(maximum_speed_mps=2.0)
        alice, bob = self._paired(safety_gate=gate)
        status_envelope = alice.make_envelope("safety.status", bob.identity.system_id, {})
        status = bob.safety_status(status_envelope)
        self.assertFalse(status["halt_requested"])

    def test_incident_report_is_durably_audited(self) -> None:
        alice, bob = self._paired()
        envelope = alice.make_envelope("incident.report", bob.identity.system_id, {"summary": "unexpected obstacle in cell x"})
        result = bob.report_incident(envelope)
        self.assertEqual(result, {"ok": True})

        rows = bob.db.read("SELECT event_type, subject FROM audit_log WHERE event_type = 'incident.reported'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subject"], alice.identity.system_id)
        ok, bad_seq = bob.audit.verify()
        self.assertTrue(ok)
        self.assertIsNone(bad_seq)

    def test_heartbeat_is_advisory_liveness_only(self) -> None:
        alice, bob = self._paired()
        envelope = alice.make_envelope("heartbeat", bob.identity.system_id, {})
        response = bob.heartbeat(envelope)
        self.assertEqual(response["type"], "heartbeat")
        self.assertIn("server_time", response)


if __name__ == "__main__":
    unittest.main()
