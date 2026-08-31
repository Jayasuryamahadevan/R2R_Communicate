from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.robotics import LocalSafetyGate


class RoboticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.robot_a = FaspHarness(root / "robot-a", "robot-a", "http://robot-a:8766")
        self.coordinator = FaspHarness(root / "coordinator", "coordinator", "http://coordinator:8766")
        hello = self.coordinator.hello(self.robot_a.id_card())
        self.coordinator.confirm_peer(self.robot_a.identity.system_id, hello["pair_code"], ["fleet."])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def reservation(self, reservation_id: str, start_ms: int, end_ms: int) -> dict:
        return self.robot_a.make_envelope("reservation.request", self.coordinator.identity.system_id, {
            "reservation_id": reservation_id, "lease_ms": 30_000,
            "segments": [{"cell": "aisle-3/cell-17", "start_ms": start_ms, "end_ms": end_ms}],
        })

    def test_conflicting_space_time_reservations_are_rejected(self) -> None:
        start = int(time.time() * 1000) + 1_000
        grant = self.coordinator.reservation_request(self.reservation("a", start, start + 5_000))
        self.assertEqual(grant["type"], "reservation.grant")
        other = FaspHarness(Path(self.temp.name) / "robot-b", "robot-b", "http://robot-b:8766")
        hello = self.coordinator.hello(other.id_card())
        self.coordinator.confirm_peer(other.identity.system_id, hello["pair_code"], ["fleet."])
        request = other.make_envelope("reservation.request", self.coordinator.identity.system_id, {
            "reservation_id": "b", "lease_ms": 30_000,
            "segments": [{"cell": "aisle-3/cell-17", "start_ms": start + 500, "end_ms": start + 4_000}],
        })
        rejected = self.coordinator.reservation_request(request)
        self.assertEqual(rejected["status"], "conflict")

    def test_concurrent_overlapping_reservations_never_both_grant(self) -> None:
        """Regression test for a real race: find_conflict() and grant()
        used to be two separate Database lock acquisitions, leaving a
        genuine window for two truly concurrent requesters to both pass
        the conflict check before either committed its grant -- caught by
        actually running real concurrent HTTP requests against a live
        harness (not exercised by the sequential property test above,
        which can't catch a race that only exists between threads).
        Reproduced here at the thread level, in-process, so it runs fast
        and never needs a real server."""
        start = int(time.time() * 1000) + 1_000
        robots = [FaspHarness(Path(self.temp.name) / f"robot-{i}", f"robot-{i}", f"http://robot-{i}:8766") for i in range(8)]
        for robot in robots:
            hello = self.coordinator.hello(robot.id_card())
            self.coordinator.confirm_peer(robot.identity.system_id, hello["pair_code"], ["fleet."])

        results: list[dict] = [None] * len(robots)  # type: ignore[list-item]
        barrier = threading.Barrier(len(robots))

        def contend(index: int, robot: FaspHarness) -> None:
            envelope = robot.make_envelope(
                "reservation.request",
                self.coordinator.identity.system_id,
                {"reservation_id": f"race-{index}", "lease_ms": 30_000, "segments": [{"cell": "aisle-9/cell-1", "start_ms": start, "end_ms": start + 5_000}]},
            )
            barrier.wait()  # maximize the chance every thread is mid-request at once
            results[index] = self.coordinator.reservation_request(envelope)

        threads = [threading.Thread(target=contend, args=(i, robot)) for i, robot in enumerate(robots)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        grants = [r for r in results if r["type"] == "reservation.grant"]
        rejects = [r for r in results if r["type"] == "reservation.reject"]
        self.assertEqual(len(grants), 1, f"expected exactly one grant among {len(robots)} concurrent contenders, got {len(grants)}: {results}")
        self.assertEqual(len(rejects), len(robots) - 1)

    def test_local_safety_gate_cannot_be_bypassed(self) -> None:
        gate = LocalSafetyGate(maximum_speed_mps=0.8)
        gate.validate(0.5, estop_clear=True, obstacle_clear=True, localization_healthy=True, reservation_active=True)
        with self.assertRaises(FaspError) as raised:
            gate.validate(0.5, estop_clear=False, obstacle_clear=True, localization_healthy=True, reservation_active=True)
        self.assertEqual(raised.exception.code, "safety.estop_active")


if __name__ == "__main__":
    unittest.main()
