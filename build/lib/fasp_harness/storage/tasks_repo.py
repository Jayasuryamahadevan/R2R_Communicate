"""Full FASP task lifecycle state machine (`tasks` table; FASP_PROTOCOL.md
ss7.2): PROPOSED -> RUNNING -> {COMPLETED | FAILED | CANCELLED}, with
CANCEL_PENDING as the transient state while a running task's cancellation
is being decided, and REJECTED for a well-formed intent whose local policy
said no before any execution began. ("ACCEPTED" is a transient in-code
step this reference harness folds directly into the RUNNING transition --
see the policy note in core.py's _handle_intent -- rather than a
separately observable row state.)

Every transition is a single guarded UPDATE (`WHERE ... AND state IN
(...)`), which is this reference harness's optimistic-concurrency
mechanism: at most one caller ever wins a given transition, so a genuine
race (e.g. a task.cancel arriving on another thread while the original
propose call is still inside adapter.handle()) resolves to exactly one
outcome instead of both sides believing they won.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..audit.chain import AuditChain
from .db import Database

TERMINAL_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED", "REJECTED"})


class TasksRepo:
    def __init__(self, db: Database, audit: AuditChain) -> None:
        self.db = db
        self.audit = audit

    def get(self, idempotency_key: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM tasks WHERE idempotency_key = ?", (idempotency_key,))
        return _row_to_task(row) if row is not None else None

    def count_inflight(self) -> int:
        """Tasks not yet in a terminal state -- the durable admission-control
        bound for the adapter work queue (`FaspHarness.max_inflight_tasks`):
        the database itself is the queue's source of truth, so this needs
        no separate in-memory counter to stay consistent across a restart."""
        row = self.db.read_one("SELECT COUNT(*) AS n FROM tasks WHERE state IN ('PROPOSED', 'RUNNING', 'CANCEL_PENDING')")
        return row["n"] if row is not None else 0

    def propose(self, idempotency_key: str, intent_id: str | None, capability: str, from_peer: str, at: str) -> bool:
        """Insert a new PROPOSED row. False if idempotency_key already exists
        -- this IS the idempotency guard (ss7.1: "MUST NOT repeat ... effect")."""
        try:
            with self.db.write() as conn:
                conn.execute(
                    "INSERT INTO tasks (idempotency_key, intent_id, capability, from_peer, state, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, 'PROPOSED', ?, ?)",
                    (idempotency_key, intent_id, capability, from_peer, at, at),
                )
                self.audit.append(conn, "task.proposed", idempotency_key, {"capability": capability, "from_peer": from_peer}, at)
        except sqlite3.IntegrityError:
            return False
        return True

    def reject(self, idempotency_key: str, error: dict[str, Any], at: str) -> bool:
        return self._transition(idempotency_key, ("PROPOSED",), "REJECTED", at, error_json=json.dumps(error))

    def start_running(self, idempotency_key: str, lease_until: str, at: str) -> bool:
        return self._transition(idempotency_key, ("PROPOSED",), "RUNNING", at, lease_until=lease_until)

    def complete(self, idempotency_key: str, result: dict[str, Any], at: str) -> bool:
        return self._transition(idempotency_key, ("RUNNING",), "COMPLETED", at, result_json=json.dumps(result))

    def fail(self, idempotency_key: str, error: dict[str, Any], at: str) -> bool:
        return self._transition(idempotency_key, ("RUNNING",), "FAILED", at, error_json=json.dumps(error))

    def request_cancel(self, idempotency_key: str, at: str) -> bool:
        return self._transition(idempotency_key, ("RUNNING",), "CANCEL_PENDING", at)

    def cancel_immediately(self, idempotency_key: str, at: str) -> bool:
        """PROPOSED or CANCEL_PENDING -> CANCELLED: no effect has committed yet."""
        return self._transition(idempotency_key, ("PROPOSED", "CANCEL_PENDING"), "CANCELLED", at)

    def resume_running(self, idempotency_key: str, at: str) -> bool:
        """CANCEL_PENDING -> RUNNING: the adapter declined to cancel (or has
        no cancel() hook), so the in-flight handle() call is still allowed
        to complete normally."""
        return self._transition(idempotency_key, ("CANCEL_PENDING",), "RUNNING", at)

    def expire_stale_leases(self, now_stamp: str) -> list[str]:
        """Resolve any row still RUNNING past its lease to FAILED/lease.expired.

        Called once at harness startup: a row can only be found RUNNING
        here if the previous process crashed mid-adapter-call. Per ss7.1, a
        resumed process MUST NOT blindly re-invoke the adapter (that could
        repeat a side effect) -- a safe terminal state is all this
        reference harness commits to.
        """
        expired: list[str] = []
        with self.db.write() as conn:
            rows = conn.execute(
                "SELECT idempotency_key FROM tasks WHERE state = 'RUNNING' AND lease_until IS NOT NULL AND lease_until < ?",
                (now_stamp,),
            ).fetchall()
            for row in rows:
                key = row["idempotency_key"]
                error = {"code": "lease.expired", "detail": "Task lease expired (process restart) before completion."}
                cursor = conn.execute(
                    "UPDATE tasks SET state = 'FAILED', error_json = ?, updated_at = ? WHERE idempotency_key = ? AND state = 'RUNNING'",
                    (json.dumps(error), now_stamp, key),
                )
                if cursor.rowcount > 0:
                    self.audit.append(conn, "task.lease_expired", key, {}, now_stamp)
                    expired.append(key)
        return expired

    def _transition(self, idempotency_key: str, from_states: tuple[str, ...], to_state: str, at: str, **fields: Any) -> bool:
        set_columns = ", ".join(f"{name} = ?" for name in fields)
        set_clause = "state = ?, updated_at = ?" + (f", {set_columns}" if set_columns else "")
        state_placeholders = ",".join("?" for _ in from_states)
        with self.db.write() as conn:
            cursor = conn.execute(
                f"UPDATE tasks SET {set_clause} WHERE idempotency_key = ? AND state IN ({state_placeholders})",
                (to_state, at, *fields.values(), idempotency_key, *from_states),
            )
            if cursor.rowcount > 0:
                self.audit.append(conn, f"task.{to_state.lower()}", idempotency_key, {"from_states": list(from_states)}, at)
            return cursor.rowcount > 0


def _row_to_task(row: Any) -> dict[str, Any]:
    return {
        "idempotency_key": row["idempotency_key"],
        "intent_id": row["intent_id"],
        "capability": row["capability"],
        "from_peer": row["from_peer"],
        "state": row["state"],
        "result": json.loads(row["result_json"]) if row["result_json"] else None,
        "error": json.loads(row["error_json"]) if row["error_json"] else None,
        "lease_until": row["lease_until"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
