"""SQLite-backed durable state for one FASP harness instance.

One physical file per system: `<state_dir>/fasp.db`, WAL mode. Schema
evolves through numbered migration files in `storage/migrations/`, applied
in order and tracked via SQLite's own `PRAGMA user_version` -- atomic with
the database file itself, so no separate version table is needed.

Deliberately synchronous: the harness itself doesn't move onto asyncio
until the transport replatform (Starlette/uvicorn) lands. All access is
serialized by a single `threading.RLock`, mirroring the concurrency model
of the flat-file `JsonState` this replaces -- every write is atomic and
every read sees a consistent snapshot, without needing SQLite's own
cross-process locking to do more than it has to at this scale (one process
per Pi/phone/laptop/robot).

The Ed25519 private key and the local admin token stay OUTSIDE this
database, as plain 0600 files (see `fasp_harness/crypto/identity.py` and
`FaspHarness.admin_token`) -- a private key doesn't benefit from
transactional guarantees, and keeping it separate means this file can be
backed up, copied, or inspected without ever containing the one secret
that must never leak.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.RLock()
        # isolation_level=None: autocommit mode, so every transaction
        # boundary in this codebase is an explicit BEGIN/COMMIT/ROLLBACK
        # (see `write()`) rather than sqlite3's implicit-transaction quirks.
        self.connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        with self.lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=5000")
            self._migrate()
        path.chmod(0o600)

    def _migrate(self) -> None:
        current = self.connection.execute("PRAGMA user_version").fetchone()[0]
        for index, migration in enumerate(sorted(MIGRATIONS_DIR.glob("*.sql")), start=1):
            if index <= current:
                continue
            self.connection.executescript(migration.read_text(encoding="utf-8"))
            self.connection.execute(f"PRAGMA user_version = {index}")

    def read(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.connection.execute(sql, parameters).fetchall()

    def read_one(self, sql: str, parameters: tuple = ()) -> sqlite3.Row | None:
        with self.lock:
            return self.connection.execute(sql, parameters).fetchone()

    def write(self) -> "_WriteTransaction":
        """One write transaction: `with db.write() as conn: conn.execute(...)`.

        Everything inside the block runs under `self.lock` and commits (or
        rolls back, on an exception) as a single atomic unit -- this is what
        lets a repo do a check-then-insert without a TOCTOU window.
        """
        return _WriteTransaction(self)


class _WriteTransaction:
    def __init__(self, db: Database) -> None:
        self._db = db

    def __enter__(self) -> sqlite3.Connection:
        self._db.lock.acquire()
        self._db.connection.execute("BEGIN IMMEDIATE")
        return self._db.connection

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            if exc_type is None:
                self._db.connection.execute("COMMIT")
            else:
                self._db.connection.execute("ROLLBACK")
        finally:
            self._db.lock.release()
        return False
