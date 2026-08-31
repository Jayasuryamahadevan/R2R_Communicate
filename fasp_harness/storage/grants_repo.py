"""Time-limited, scoped delegated authority, backed by SQLite (`grants` table).

See fasp_harness/policy/grants.py for how a grant is actually evaluated
against an intent; this repo only stores and retrieves them.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..crypto.envelope import b64
from .db import Database


def compute_digest(grant_id: str, subject_peer: str, capability_prefixes: list[str], issued_at: str, expires_at: str) -> str:
    """A stable content digest an intent can reference alongside `grant_id`,
    matching the `grant: {"id": ..., "digest": ...}` shape FASP_PROTOCOL.md
    ss5 puts on envelopes."""
    payload = json.dumps(
        {"grant_id": grant_id, "subject_peer": subject_peer, "capability_prefixes": sorted(capability_prefixes), "issued_at": issued_at, "expires_at": expires_at},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha-256:" + b64(hashlib.sha256(payload).digest())


class GrantsRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def issue(
        self,
        grant_id: str,
        issuer: str,
        subject_peer: str,
        capability_prefixes: list[str],
        issued_at: str,
        expires_at: str,
        purpose: str | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        digest = compute_digest(grant_id, subject_peer, capability_prefixes, issued_at, expires_at)
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO grants (grant_id, issuer, subject_peer, capability_prefixes_json, digest, purpose, constraints_json, issued_at, expires_at, revoked_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (grant_id, issuer, subject_peer, json.dumps(capability_prefixes), digest, purpose, json.dumps(constraints) if constraints is not None else None, issued_at, expires_at),
            )
        grant = self.get(grant_id)
        assert grant is not None
        return grant

    def get(self, grant_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM grants WHERE grant_id = ?", (grant_id,))
        return _row_to_grant(row) if row is not None else None

    def revoke(self, grant_id: str, revoked_at: str) -> bool:
        with self.db.write() as conn:
            cursor = conn.execute("UPDATE grants SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL", (revoked_at, grant_id))
            return cursor.rowcount > 0

    def for_subject(self, subject_peer: str) -> list[dict[str, Any]]:
        return [_row_to_grant(row) for row in self.db.read("SELECT * FROM grants WHERE subject_peer = ? ORDER BY issued_at DESC", (subject_peer,))]


def _row_to_grant(row: Any) -> dict[str, Any]:
    return {
        "grant_id": row["grant_id"],
        "issuer": row["issuer"],
        "subject_peer": row["subject_peer"],
        "capability_prefixes": json.loads(row["capability_prefixes_json"]),
        "digest": row["digest"],
        "purpose": row["purpose"],
        "constraints": json.loads(row["constraints_json"]) if row["constraints_json"] else None,
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
        "revoked_at": row["revoked_at"],
    }
