"""The package must ship everything it needs to run once installed.

This exists because it was once not true: the SQL migrations were not
declared as package data, so a wheel install produced a harness that built
an empty database and failed on its first query. An editable install --
which is what CI and every developer machine used -- masked it completely,
because the files were on disk regardless.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fasp_harness.storage.db import MIGRATIONS_DIR, Database

EXPECTED_TABLES = {
    "peers",
    "envelopes_inbox",
    "tasks",
    "grants",
    "revocations",
    "audit_log",
    "artifacts",
    "streams",
    "stream_packets",
    "reservations",
    "reservation_segments",
    "safety_events",
    "leases",
    "outbox",
    "missions",
    "twin_observations",
}


class AbbTwinPackagingTests(unittest.TestCase):
    """The twin must ship the RAPID module it executes, and it must be the same
    module the commissioning document tells an ABB programmer to load. Two
    copies that drift would mean the twin proves something about a file nobody
    runs."""

    def test_the_pilot_module_is_packaged_with_the_twin(self) -> None:
        from fasp_harness.fleet.abb_twin.scenarios import MODULE_PATH

        self.assertTrue(MODULE_PATH.exists(), f"{MODULE_PATH} is not being packaged; the twin cannot run from a wheel.")
        self.assertIn("FASP_PilotMain", MODULE_PATH.read_text(encoding="utf-8"))

    def test_the_packaged_module_matches_the_one_operators_are_given(self) -> None:
        from fasp_harness.fleet.abb_twin.scenarios import MODULE_PATH

        operator_copy = Path(__file__).resolve().parents[1] / "examples" / "abb_gofa" / "FASP_Pilot.mod"
        if not operator_copy.exists():  # a wheel install has no examples/ tree
            self.skipTest("running outside a source checkout")
        self.assertEqual(
            MODULE_PATH.read_bytes(),
            operator_copy.read_bytes(),
            "The packaged RAPID module has drifted from examples/abb_gofa/FASP_Pilot.mod; the twin would test a module nobody loads.",
        )


class PackagingTests(unittest.TestCase):
    def test_migrations_are_discoverable_from_the_installed_package(self) -> None:
        migrations = sorted(MIGRATIONS_DIR.glob("*.sql"))
        self.assertTrue(migrations, f"No migrations found under {MIGRATIONS_DIR}; they are not being packaged.")
        self.assertEqual([path.name.split("_")[0] for path in migrations], [f"{index:04d}" for index in range(1, len(migrations) + 1)], "Migrations must be numbered contiguously from 0001.")

    def test_a_fresh_database_has_every_expected_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "fasp.db")
            tables = {row["name"] for row in db.read("SELECT name FROM sqlite_master WHERE type = 'table'")}
            self.assertTrue(EXPECTED_TABLES.issubset(tables), f"missing: {sorted(EXPECTED_TABLES - tables)}")

    def test_the_schema_version_matches_the_migration_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "fasp.db")
            version = db.read_one("PRAGMA user_version")[0]
            self.assertEqual(version, len(list(MIGRATIONS_DIR.glob("*.sql"))))

    def test_migrations_are_idempotent_across_reopen(self) -> None:
        """Reopening must not re-run an applied migration -- `user_version`
        is what makes that safe, and a regression here corrupts live data."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fasp.db"
            first = Database(path)
            first.connection.execute("INSERT INTO leases (name, holder, fence, acquired_at, renewed_at, expires_at_ms) VALUES ('x', 'n', 1, 'a', 'b', 1)")
            second = Database(path)
            self.assertEqual(second.read_one("SELECT COUNT(*) AS n FROM leases")["n"], 1)


if __name__ == "__main__":
    unittest.main()
