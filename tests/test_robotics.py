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


class DilatedReservationOverTheWireTests(unittest.TestCase):
    """The dilated reservation reaching the arbiter through a signed envelope.

    The library-level behaviour is covered in tests/test_spatial_reservation.py.
    What is asserted here is that it is actually reachable by a peer --
    that guard bands and volumes survive the envelope path, the
    authorisation check and the dispatch table, rather than being a
    facility only local code can use.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.coordinator = FaspHarness(root / "coordinator", "coordinator", "http://coordinator:8766")
        self.robots = {}
        for name in ("robot-a", "robot-b", "robot-c"):
            harness = FaspHarness(root / name, name, f"http://{name}:8766")
            hello = self.coordinator.hello(harness.id_card())
            self.coordinator.confirm_peer(harness.identity.system_id, hello["pair_code"], ["fleet."])
            self.robots[name] = harness

    def tearDown(self) -> None:
        self.temp.cleanup()

    def request(self, robot: str, payload: dict) -> dict:
        envelope = self.robots[robot].make_envelope("reservation.request", self.coordinator.identity.system_id, payload)
        return self.coordinator.reservation_request(envelope)

    @staticmethod
    def box(centre: float, half_width: float) -> dict:
        return {
            "frame_id": "site",
            "minimum_m": [centre - half_width, -half_width, -0.5],
            "maximum_m": [centre + half_width, half_width, 2.0],
        }

    def test_a_guarded_segment_survives_the_envelope_path(self) -> None:
        start = int(time.time() * 1000) + 1_000
        granted = self.request("robot-a", {
            "reservation_id": "guarded", "lease_ms": 30_000,
            "segments": [{"cell": "aisle-3/cell-17", "start_ms": start, "end_ms": start + 2_000, "guard_ms": 400}],
        })
        self.assertEqual(granted["type"], "reservation.grant")
        self.assertEqual(granted["segments"][0]["guard_ms"], 400)

    def test_two_peers_apart_on_paper_conflict_once_their_clocks_are_admitted(self) -> None:
        start = int(time.time() * 1000) + 1_000
        self.request("robot-a", {
            "reservation_id": "a", "segments": [{"cell": "aisle-3/cell-17", "start_ms": start, "end_ms": start + 2_000, "guard_ms": 300}],
        })
        rejected = self.request("robot-b", {
            "reservation_id": "b", "segments": [{"cell": "aisle-3/cell-17", "start_ms": start + 2_050, "end_ms": start + 4_000, "guard_ms": 300}],
        })
        self.assertEqual(rejected["status"], "conflict")

    def test_peers_sharing_no_cell_vocabulary_still_conflict_physically(self) -> None:
        """Two vendors, two cell maps, one floor. Neither name means
        anything to the other, and the boxes are what stop them meeting."""
        start = int(time.time() * 1000) + 1_000
        granted = self.request("robot-a", {
            "reservation_id": "a",
            "segments": [{"cell": "vendor-x/aisle-3", "start_ms": start, "end_ms": start + 2_000, "volume": self.box(0.0, 2.0)}],
        })
        self.assertEqual(granted["type"], "reservation.grant")

        rejected = self.request("robot-b", {
            "reservation_id": "b",
            "segments": [{"cell": "vendor-y/zone-14", "start_ms": start + 500, "end_ms": start + 1_500, "volume": self.box(1.0, 2.0)}],
        })
        self.assertEqual(rejected["status"], "conflict")
        self.assertEqual(rejected["basis"], "volume")

        elsewhere = self.request("robot-c", {
            "reservation_id": "c",
            "segments": [{"cell": "vendor-z/dock-2", "start_ms": start + 500, "end_ms": start + 1_500, "volume": self.box(60.0, 2.0)}],
        })
        self.assertEqual(elsewhere["type"], "reservation.grant")

    def test_an_abusive_guard_is_refused_at_the_boundary_not_granted(self) -> None:
        """A peer is not trusted to declare its own dilation without bound."""
        start = int(time.time() * 1000) + 1_000
        with self.assertRaises(FaspError):
            self.request("robot-a", {
                "reservation_id": "greedy",
                "segments": [{"cell": "aisle-3/cell-17", "start_ms": start, "end_ms": start + 1_000, "guard_ms": 600_000}],
            })

    def test_an_oversized_volume_is_refused_at_the_boundary(self) -> None:
        start = int(time.time() * 1000) + 1_000
        with self.assertRaises(FaspError):
            self.request("robot-a", {
                "reservation_id": "greedy",
                "segments": [{"cell": "aisle-3/cell-17", "start_ms": start, "end_ms": start + 1_000, "volume": self.box(0.0, 5_000.0)}],
            })

    def test_an_unpaired_peer_still_cannot_reserve_anything(self) -> None:
        """The new fields change what a reservation says, not who may make
        one."""
        stranger = FaspHarness(Path(self.temp.name) / "stranger", "stranger", "http://stranger:8766")
        start = int(time.time() * 1000) + 1_000
        envelope = stranger.make_envelope("reservation.request", self.coordinator.identity.system_id, {
            "reservation_id": "x",
            "segments": [{"cell": "aisle-3/cell-17", "start_ms": start, "end_ms": start + 1_000, "guard_ms": 100}],
        })
        with self.assertRaises(FaspError):
            self.coordinator.reservation_request(envelope)
