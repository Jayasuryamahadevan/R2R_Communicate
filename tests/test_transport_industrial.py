"""The industrial HTTP surface: probes, Layer 1 evidence, and fleet views."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from fasp_harness.core import FaspHarness
from fasp_harness.edge.health import HealthRegistry
from fasp_harness.fleet.adapter import FleetRegistry
from fasp_harness.fleet.model import Pose
from fasp_harness.fleet.service import MissionService
from fasp_harness.fleet.simulated import SimulatedFleetManager
from fasp_harness.safety.drivers import SimulatedSafetyController
from fasp_harness.safety.interlock import SafetySupervisor
from fasp_harness.transport.http_app import create_app, default_health


class IndustrialTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.controller = SimulatedSafetyController()
        self.supervisor = SafetySupervisor(self.controller, stale_after_s=60.0)
        self.supervisor.poll()

        fleet = SimulatedFleetManager("acme", nodes={"dock-7": Pose(20.0, 0.0)})
        fleet.add_vehicle("AGV1")
        registry = FleetRegistry()
        registry.register(fleet)

        self.harness = FaspHarness(root / "node", "node", "http://node:8766", supervisor=self.supervisor)
        self.harness.missions = MissionService(self.harness.db, registry, audit=self.harness.audit, supervisor=self.supervisor)
        self.client = TestClient(create_app(self.harness))
        self.admin = {"X-FASP-Admin-Token": self.harness.admin_token}

    def tearDown(self) -> None:
        self.harness.close()
        self.temp.cleanup()

    def test_probes_are_public_and_minimal(self) -> None:
        """An orchestrator needs a status code; the names of internal checks
        are not something to hand to anyone who can reach the port."""
        for path in ("/livez", "/readyz"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(set(response.json()), {"ok", "state"})

    def test_detail_requires_the_admin_token(self) -> None:
        for path in ("/health/detail", "/safety", "/fleet"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)
                self.assertEqual(self.client.get(path, headers=self.admin).status_code, 200)

    def test_readiness_fails_while_a_dependency_is_down(self) -> None:
        health = default_health(self.harness)
        health.register("vendor", lambda: (False, "fleet manager unreachable"))
        client = TestClient(create_app(self.harness, health))
        self.assertEqual(client.get("/readyz").status_code, 503)
        self.assertEqual(client.get("/livez").status_code, 200, "A dependency being down is not a reason to restart.")

    def test_a_wedged_process_fails_liveness(self) -> None:
        health = HealthRegistry()
        health.register("database", lambda: (False, "disk gone"), critical=True)
        health.mark_started()
        client = TestClient(create_app(self.harness, health))
        self.assertEqual(client.get("/livez").status_code, 503)

    def test_safety_evidence_is_read_only_and_complete(self) -> None:
        body = self.client.get("/safety", headers=self.admin).json()
        self.assertTrue(body["observed_only"])
        self.assertEqual(body["layer"], 1)
        self.assertFalse(body["controller"]["real_hardware"])
        self.assertIn("does not implement", body["note"])

    def test_there_is_no_route_that_clears_a_halt(self) -> None:
        self.supervisor.demand_halt("operator", "test", origin="peer")
        for method in ("post", "put", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)("/safety", headers=self.admin)
                self.assertEqual(response.status_code, 405)
        self.assertTrue(self.supervisor.latched)

    def test_the_fleet_view_reports_vehicles_missions_and_safety(self) -> None:
        body = self.client.get("/fleet", headers=self.admin).json()
        self.assertEqual(len(body["vehicles"]), 1)
        self.assertIn("acme", [entry["fleet"] for entry in body["fleet_health"]])
        self.assertFalse(body["safety"]["halt_requested"])

    def test_metrics_expose_the_safety_and_mission_gauges(self) -> None:
        self.supervisor.demand_halt("operator", "test", origin="peer")
        text = self.client.get("/metrics", headers=self.admin).text
        self.assertIn("fasp_safety_halt_latched 1", text)
        self.assertIn("fasp_safety_controller_reachable 1", text)

    def test_a_node_without_a_supervisor_reports_capability_unavailable(self) -> None:
        bare = FaspHarness(Path(self.temp.name) / "bare", "bare", "http://bare:8766")
        client = TestClient(create_app(bare))
        response = client.get("/safety", headers={"X-FASP-Admin-Token": bare.admin_token})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "capability.unavailable")
        bare.close()

    def test_the_profile_advertises_the_layer_model(self) -> None:
        layers = self.client.get("/profile").json()["layers"]
        self.assertEqual(layers[0]["permitted_interactions"], ["observe"])
        self.assertFalse(layers[0]["implemented_here"])


if __name__ == "__main__":
    unittest.main()
