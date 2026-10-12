"""The SQLite backup API must produce a consistent snapshot with WAL enabled."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from fasp_harness.storage.db import Database


class DatabaseBackupTests(unittest.TestCase):
    def test_online_backup_includes_uncheckpointed_commits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = Database(root / "live" / "fasp.db")
            with source.write() as conn:
                conn.execute(
                    "INSERT INTO peers (peer_id, public_key, card_json, state, allowed_capability_prefixes_json, pair_code, seen_at) "
                    "VALUES ('peer', 'pub', '{}', 'pending', '[]', 'code', '2026-01-01T00:00:00Z')"
                )
            target = root / "backups" / "copy.db"
            old_mask = os.umask(0)
            try:
                source.backup(target)
            finally:
                os.umask(old_mask)
            restored = Database(target)
            self.assertIsNotNone(restored.read_one("SELECT peer_id FROM peers WHERE peer_id = 'peer'"))
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                source.backup(source.path)


if __name__ == "__main__":
    unittest.main()
