"""Idempotency journal for intent.propose (`tasks` table, minimal Phase-2 shape).

Phase 4 extends this into the full PROPOSED/ACCEPTED/RUNNING/... task
lifecycle state machine; for now this only needs to answer "have I already
produced a result for this idempotency_key?" and record one exactly once.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .db import Database


class TasksRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get_result(self, idempotency_key: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT result_json FROM tasks WHERE idempotency_key = ?", (idempotency_key,))
        return json.loads(row["result_json"]) if row is not None else None

    def record_if_new(
        self,
        idempotency_key: str,
        intent_id: str | None,
        capability: str,
        from_peer: str,
        result: dict[str, Any],
        created_at: str,
    ) -> bool:
        """Record `result` for a new idempotency_key. False if one already existed
        (a concurrent duplicate raced in first; the caller should use that result)."""
        try:
            with self.db.write() as conn:
                conn.execute(
                    "INSERT INTO tasks (idempotency_key, intent_id, capability, from_peer, result_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (idempotency_key, intent_id, capability, from_peer, json.dumps(result), created_at),
                )
        except sqlite3.IntegrityError:
            return False
        return True
