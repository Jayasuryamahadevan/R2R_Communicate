"""Tamper-evident, hash-chained append-only audit log (FASP_PROTOCOL.md ss11).

Every grant decision, task-lifecycle transition, and revocation/pairing
event is appended here in the SAME transaction as the underlying state
change it documents -- that's what makes "it happened" and "it's audited"
atomic, rather than two facts that could drift apart on a crash. Detail
payloads are deliberately minimal: ids, decisions, digests -- never intent
payload contents or raw sensor data (ss11: "Audit records SHOULD exclude
task payloads and sensitive raw data by default").
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from ..crypto.canonical import canonicalize
from ..storage.db import Database

GENESIS_PREFIX = b"fasp-audit-genesis:"


def _row_hash(prev_hash: str, seq: int, ts: str, event_type: str, subject: str, detail: dict[str, Any]) -> str:
    payload = canonicalize({"seq": seq, "ts": ts, "event_type": event_type, "subject": subject, "detail": detail, "prev_hash": prev_hash})
    return hashlib.sha256(payload).hexdigest()


class AuditChain:
    def __init__(self, db: Database, system_id: str) -> None:
        self.db = db
        self._genesis = hashlib.sha256(GENESIS_PREFIX + system_id.encode("utf-8")).hexdigest()

    def append(self, conn: sqlite3.Connection, event_type: str, subject: str, detail: dict[str, Any], ts: str) -> None:
        """Append one entry. MUST be called with an already-open write
        transaction (the `conn` a `Database.write()` block hands you) so
        the audit entry commits atomically with whatever it documents.
        """
        prev_row = conn.execute("SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = prev_row["row_hash"] if prev_row is not None else self._genesis
        seq = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM audit_log").fetchone()["next_seq"]
        row_hash = _row_hash(prev_hash, seq, ts, event_type, subject, detail)
        conn.execute(
            "INSERT INTO audit_log (seq, ts, event_type, subject, detail_json, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (seq, ts, event_type, subject, json.dumps(detail), prev_hash, row_hash),
        )

    def verify(self) -> tuple[bool, int | None]:
        """Recompute every row's hash from genesis. Returns (ok, first_bad_seq)."""
        prev_hash = self._genesis
        for row in self.db.read("SELECT * FROM audit_log ORDER BY seq"):
            expected = _row_hash(prev_hash, row["seq"], row["ts"], row["event_type"], row["subject"], json.loads(row["detail_json"]))
            if row["prev_hash"] != prev_hash or row["row_hash"] != expected:
                return False, row["seq"]
            prev_hash = row["row_hash"]
        return True, None
