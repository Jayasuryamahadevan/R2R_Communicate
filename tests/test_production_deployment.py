"""Production startup checks use the actual listener and refuse corrupted state."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.deployment import NodeConfig, build_node
from fasp_harness.protocol.errors import FaspError
from fasp_harness.security.posture import DeploymentConfig, SecurityProfile


class ProductionNodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_production_node_uses_listener_tls_and_mtls_details(self) -> None:
        config = NodeConfig(state_dir=self.root / "tls", profile=SecurityProfile.PRODUCTION)
        listener = DeploymentConfig(
            profile=SecurityProfile.PRODUCTION,
            host="0.0.0.0",
            state_dir=config.state_dir,
            tls_cert=Path("/mounted/tls.crt"),
            tls_key=Path("/mounted/tls.key"),
            tls_client_ca=Path("/mounted/ca.crt"),
        )
        node = build_node(config, security_posture=listener)
        try:
            self.assertTrue(node.harness.audit.verify()[0])
        finally:
            node.stop()

    def test_production_node_refuses_missing_mtls_even_with_https_base_url(self) -> None:
        config = NodeConfig(
            state_dir=self.root / "without-mtls",
            base_url="https://example.internal:8766",
            profile=SecurityProfile.PRODUCTION,
        )
        listener = DeploymentConfig(
            profile=SecurityProfile.PRODUCTION,
            host="0.0.0.0",
            state_dir=config.state_dir,
            tls_cert=Path("/mounted/tls.crt"),
            tls_key=Path("/mounted/tls.key"),
        )
        with self.assertRaises(FaspError) as raised:
            build_node(config, security_posture=listener)
        self.assertEqual(raised.exception.code, "policy.insecure_configuration")

    def test_corrupt_audit_history_refuses_hardened_startup(self) -> None:
        state = self.root / "tampered"
        instance = FaspHarness(state, "tampered", "http://127.0.0.1:8766")
        with instance.db.write() as conn:
            instance.audit.append(conn, "initial", "node", {}, "2026-01-01T00:00:00Z")
        instance.close()
        from fasp_harness.storage.db import Database

        database = Database(state / "fasp.db")
        with database.write() as conn:
            conn.execute("UPDATE audit_log SET row_hash = 'altered' WHERE seq = 1")
        config = NodeConfig(state_dir=state, profile=SecurityProfile.HARDENED)
        listener = DeploymentConfig(
            profile=SecurityProfile.HARDENED,
            host="0.0.0.0",
            state_dir=state,
            tls_cert=Path("/mounted/tls.crt"),
            tls_key=Path("/mounted/tls.key"),
        )
        with self.assertRaises(FaspError) as raised:
            build_node(config, security_posture=listener)
        self.assertEqual(raised.exception.code, "policy.insecure_configuration")


if __name__ == "__main__":
    unittest.main()
