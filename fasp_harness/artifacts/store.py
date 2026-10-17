"""Immutable, content-addressed artifact storage (FASP_PROTOCOL.md ss11).

Large results don't belong inline in a signed, 64 KiB-capped envelope
(ss5); this stores them by digest under `<state_dir>/artifacts/` and lets
a task result carry just a reference. Metadata lives in the `artifacts`
table (see migrations/0004_artifacts.sql); bytes live on disk, named by
their own digest so two identical payloads are stored once.

This intentionally has no separate storage/artifacts_repo.py -- unlike
peers/tasks/grants, an artifact's metadata and its bytes are two facets of
the exact same operation (you can't sensibly write one without the other),
so splitting them into a metadata-only repo plus a content-store class
would just be indirection with no caller that wants one without the other.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..protocol.errors import FaspError
from ..storage.db import Database
from ..timestamps import now, parse_stamp, stamp

DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024


class ArtifactStore:
    def __init__(self, db: Database, state_dir: Path, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES) -> None:
        self.db = db
        self.directory = state_dir / "artifacts"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.max_total_bytes = max_total_bytes
        self._put_lock = threading.Lock()

    def total_bytes(self) -> int:
        row = self.db.read_one("SELECT COALESCE(SUM(size_bytes), 0) AS total FROM artifacts")
        return int(row["total"])

    def put(self, data: bytes, media_type: str, created_by: str, at: str, retention: timedelta | None = None) -> dict[str, Any]:
        """Store `data`, returning its artifact record. Storing the same
        bytes twice returns the original record (content-addressed dedup).

        Serialised with `_put_lock`: the dedup lookup and the capacity read
        are separate statements, so two concurrent puts of the same bytes
        would both pass them and one would then raise a raw
        sqlite3.IntegrityError from the UNIQUE digest constraint (and two
        large puts could both clear the capacity bar).
        """
        with self._put_lock:
            self.purge_expired()
            return self._put(data, media_type, created_by, at, retention)

    def purge_expired(self, *, at: str | None = None) -> int:
        """Delete artifacts whose `retention_until` has passed.

        Retention is written into every record, so it is enforced here
        rather than left as documentation: without a sweep the size cap
        fills with expired bytes and every later put fails permanently.
        Bytes are removed best-effort after the metadata commits; a stray
        file is a leak, not a correctness problem.
        """
        cutoff = at or stamp(now())
        rows = self.db.read(
            "SELECT artifact_id, storage_path FROM artifacts WHERE retention_until IS NOT NULL AND retention_until <= ?",
            (cutoff,),
        )
        if not rows:
            return 0
        with self.db.write() as conn:
            for row in rows:
                conn.execute("DELETE FROM artifact_access WHERE artifact_id = ?", (row["artifact_id"],))
                conn.execute("DELETE FROM artifacts WHERE artifact_id = ?", (row["artifact_id"],))
        for row in rows:
            try:
                Path(row["storage_path"]).unlink(missing_ok=True)
            except OSError:
                pass
        return len(rows)

    def _put(self, data: bytes, media_type: str, created_by: str, at: str, retention: timedelta | None = None) -> dict[str, Any]:
        digest = "sha-256:" + hashlib.sha256(data).hexdigest()
        existing = self.db.read_one("SELECT * FROM artifacts WHERE digest = ?", (digest,))
        if existing is not None:
            with self.db.write() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO artifact_access (artifact_id, peer_id) VALUES (?, ?)",
                    (existing["artifact_id"], created_by),
                )
            return _row_to_artifact(existing)

        if self.total_bytes() + len(data) > self.max_total_bytes:
            raise FaspError("resource.exhausted", "Artifact storage limit reached; cannot store a new artifact.")

        artifact_id = "artifact-" + secrets.token_urlsafe(12)
        hex_digest = digest.split(":", 1)[1]
        shard = self.directory / hex_digest[:2]
        shard.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = shard / hex_digest
        descriptor, temporary = tempfile.mkstemp(prefix=".artifact-", dir=shard)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

        retention_until = stamp(parse_stamp(at) + retention) if retention is not None else None
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO artifacts (artifact_id, media_type, digest, size_bytes, created_by, created_at, retention_until, storage_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact_id, media_type, digest, len(data), created_by, at, retention_until, str(path)),
            )
            conn.execute(
                "INSERT INTO artifact_access (artifact_id, peer_id) VALUES (?, ?)",
                (artifact_id, created_by),
            )
        artifact = self.get(artifact_id)
        assert artifact is not None
        return artifact

    def get(self, artifact_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,))
        return _row_to_artifact(row) if row is not None else None

    def can_fetch(self, artifact_id: str, peer_id: str) -> bool:
        row = self.db.read_one(
            "SELECT 1 FROM artifact_access WHERE artifact_id = ? AND peer_id = ?",
            (artifact_id, peer_id),
        )
        return row is not None

    def read_bytes(self, artifact_id: str) -> bytes | None:
        artifact = self.get(artifact_id)
        if artifact is None:
            return None
        try:
            data = Path(artifact["storage_path"]).read_bytes()
        except OSError as exc:
            raise FaspError("storage.artifact_unavailable", "Stored artifact cannot be read.") from exc
        if len(data) != artifact["size_bytes"] or "sha-256:" + hashlib.sha256(data).hexdigest() != artifact["digest"]:
            raise FaspError("storage.artifact_corrupt", "Stored artifact failed its integrity check.")
        return data


def _row_to_artifact(row: Any) -> dict[str, Any]:
    return {
        "artifact_id": row["artifact_id"],
        "media_type": row["media_type"],
        "digest": row["digest"],
        "size_bytes": row["size_bytes"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "retention_until": row["retention_until"],
        "storage_path": row["storage_path"],
    }
