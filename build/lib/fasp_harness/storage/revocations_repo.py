"""Peer revocation state, backed by SQLite (`revocations` table).

Presence of a row means the peer is currently revoked and MUST be rejected
regardless of its `peers.state` (FASP_PROTOCOL.md ss12). `PeersRepo.confirm()`
clears the row on a successful re-pairing -- that ceremony IS the
"require re-pairing" step ss12 calls for after a suspected key compromise.
"""

from __future__ import annotations

from typing import Any

from ..audit.chain import AuditChain
from .db import Database


class RevocationsRepo:
    def __init__(self, db: Database, audit: AuditChain) -> None:
        self.db = db
        self.audit = audit

    def revoke(self, peer_id: str, revoked_at: str, reason: str, revocation_ref: str | None = None) -> None:
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO revocations (peer_id, revoked_at, reason, revocation_ref) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(peer_id) DO UPDATE SET revoked_at = excluded.revoked_at, reason = excluded.reason, revocation_ref = excluded.revocation_ref",
                (peer_id, revoked_at, reason, revocation_ref),
            )
            self.audit.append(conn, "peer.revoked", peer_id, {"reason": reason, "revocation_ref": revocation_ref}, revoked_at)

    def get(self, peer_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM revocations WHERE peer_id = ?", (peer_id,))
        if row is None:
            return None
        return {"peer_id": row["peer_id"], "revoked_at": row["revoked_at"], "reason": row["reason"], "revocation_ref": row["revocation_ref"]}

    def is_revoked(self, peer_id: str) -> bool:
        return self.db.read_one("SELECT 1 FROM revocations WHERE peer_id = ?", (peer_id,)) is not None
