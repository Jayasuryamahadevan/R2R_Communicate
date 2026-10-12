"""The package must ship everything it needs to run once installed.

This exists because it was once not true: the SQL migrations were not
declared as package data, so a wheel install produced a harness that built
an empty database and failed on its first query. An editable install --
which is what CI and every developer machine used -- masked it completely,
because the files were on disk regardless.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from fasp_harness.storage.db import MIGRATIONS_DIR, Database
from fasp_harness.storage.work_items_repo import WorkItemsRepo

EXPECTED_TABLES = {
    "peers",
    "envelopes_inbox",
    "work_items",
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
    "twin_observations",
}


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

    def test_unified_work_migration_preserves_intents_and_missions(self) -> None:
        """The lifecycle consolidation must upgrade existing node databases."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fasp.db"
            connection = sqlite3.connect(path)
            migrations = sorted(MIGRATIONS_DIR.glob("*.sql"))
            for version, migration in enumerate(migrations[:7], start=1):
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + migration.read_text(encoding="utf-8")
                    + f"\nPRAGMA user_version = {version};\nCOMMIT;"
                )
            connection.execute(
                "INSERT INTO tasks (idempotency_key, intent_id, capability, from_peer, state, error_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("intent-1", "request-1", "observe.status.v1", "peer-1", "REJECTED", '{"code":"denied"}', "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"),
            )
            connection.execute(
                "INSERT INTO missions (mission_id, requested_by, state, priority, definition_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("mission-1", "peer-2", "COMPLETED", 2, '{"destination":"dock-7"}', "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z"),
            )
            connection.commit()
            connection.close()

            db = Database(path)
            work_items = WorkItemsRepo(db)
            intent = work_items.get("intent:intent-1", "intent")
            mission = work_items.get("mission:mission-1", "mission")
            self.assertEqual((intent["state"], intent["phase"], intent["error"]), ("failed", "rejected", {"code": "denied"}))
            self.assertEqual((mission["state"], mission["payload"], mission["priority"]), ("succeeded", {"destination": "dock-7"}, 2))


if __name__ == "__main__":
    unittest.main()
