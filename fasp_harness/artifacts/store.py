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
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..storage.db import Database
from ..timestamps import parse_stamp, stamp


class ArtifactStore:
    def __init__(self, db: Database, state_dir: Path) -> None:
        self.db = db
        self.directory = state_dir / "artifacts"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def put(self, data: bytes, media_type: str, created_by: str, at: str, retention: timedelta | None = None) -> dict[str, Any]:
        """Store `data`, returning its artifact record. Storing the same
        bytes twice returns the original record (content-addressed dedup)."""
        digest = "sha-256:" + hashlib.sha256(data).hexdigest()
        existing = self.db.read_one("SELECT * FROM artifacts WHERE digest = ?", (digest,))
        if existing is not None:
            return _row_to_artifact(existing)

        artifact_id = "artifact-" + secrets.token_urlsafe(12)
        hex_digest = digest.split(":", 1)[1]
        shard = self.directory / hex_digest[:2]
        shard.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = shard / hex_digest
        path.write_bytes(data)
        path.chmod(0o600)

        retention_until = stamp(parse_stamp(at) + retention) if retention is not None else None
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO artifacts (artifact_id, media_type, digest, size_bytes, created_by, created_at, retention_until, storage_path) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact_id, media_type, digest, len(data), created_by, at, retention_until, str(path)),
            )
        artifact = self.get(artifact_id)
        assert artifact is not None
        return artifact

    def get(self, artifact_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,))
        return _row_to_artifact(row) if row is not None else None

    def read_bytes(self, artifact_id: str) -> bytes | None:
        artifact = self.get(artifact_id)
        if artifact is None:
            return None
        return Path(artifact["storage_path"]).read_bytes()


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
