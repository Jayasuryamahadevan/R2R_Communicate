"""The shared durable lifecycle for every unit of work.

Intent executions and fleet missions have different payloads and execution
rules, but they share one small lifecycle and one persistence model:
queued -> running -> succeeded / failed / cancelled. Domain services keep
their own data in payload and metadata; this repository owns identity,
state changes, idempotency, and timestamps.
"""

from __future__ import annotations

import json
import sqlite3
from enum import StrEnum
from typing import Any

from ..audit.chain import AuditChain
from ..protocol.errors import AdmissionRejected
from .db import Database


class WorkState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_STATES = frozenset({WorkState.QUEUED.value, WorkState.RUNNING.value})
TERMINAL_STATES = frozenset({WorkState.SUCCEEDED.value, WorkState.FAILED.value, WorkState.CANCELLED.value})

_UNSET = object()


def _decode(value: str | None) -> Any:
    return json.loads(value) if value is not None else None


def _row_to_work_item(row: Any) -> dict[str, Any]:
    return {
        "work_id": row["work_id"],
        "kind": row["kind"],
        "owner": row["owner"],
        "idempotency_key": row["idempotency_key"],
        "capability": row["capability"],
        "intent_id": row["intent_id"],
        "state": row["state"],
        "phase": row["phase"],
        "payload": _decode(row["payload_json"]),
        "metadata": _decode(row["metadata_json"]) or {},
        "result": _decode(row["result_json"]),
        "error": _decode(row["error_json"]),
        "lease_until": row["lease_until"],
        "priority": int(row["priority"]),
        "assigned_to": row["assigned_to"],
        "fence": row["fence"],
        "dispatched_at": row["dispatched_at"],
        "deadline_at": row["deadline_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class WorkItemsRepo:
    """Small, domain-neutral persistence API for queued work."""

    def __init__(self, db: Database, audit: AuditChain | None = None) -> None:
        self.db = db
        self.audit = audit

    def get(self, work_id: str, kind: str | None = None) -> dict[str, Any] | None:
        if kind is None:
            row = self.db.read_one("SELECT * FROM work_items WHERE work_id = ?", (work_id,))
        else:
            row = self.db.read_one("SELECT * FROM work_items WHERE work_id = ? AND kind = ?", (work_id, kind))
        return _row_to_work_item(row) if row is not None else None

    def find_by_key(self, kind: str, key: str) -> dict[str, Any] | None:
        row = self.db.read_one(
            "SELECT * FROM work_items WHERE kind = ? AND idempotency_key = ?",
            (kind, key),
        )
        return _row_to_work_item(row) if row is not None else None

    def create(
        self,
        *,
        work_id: str,
        kind: str,
        owner: str,
        idempotency_key: str,
        at: str,
        capability: str | None = None,
        intent_id: str | None = None,
        payload: Any = None,
        metadata: dict[str, Any] | None = None,
        priority: int = 0,
        deadline_at: str | None = None,
        phase: str | None = None,
        audit_event: str | None = None,
        audit_detail: dict[str, Any] | None = None,
        max_active: int | None = None,
    ) -> bool:
        try:
            with self.db.write() as conn:
                # Resolve idempotency before capacity: an existing result is
                # readable even while unrelated work fills the queue. The
                # count and insert share BEGIN IMMEDIATE across connections.
                existing = conn.execute(
                    "SELECT 1 FROM work_items WHERE work_id = ? OR (kind = ? AND idempotency_key = ?)",
                    (work_id, kind, idempotency_key),
                ).fetchone()
                if existing is not None:
                    return False
                if max_active is not None:
                    active = conn.execute(
                        "SELECT COUNT(*) AS n FROM work_items WHERE kind = ? AND state IN ('queued', 'running')", (kind,),
                    ).fetchone()["n"]
                    if active >= max_active:
                        raise AdmissionRejected()
                conn.execute(
                    "INSERT INTO work_items (work_id, kind, owner, idempotency_key, capability, intent_id, "
                    "state, phase, payload_json, metadata_json, priority, deadline_at, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)",
                    (
                        work_id,
                        kind,
                        owner,
                        idempotency_key,
                        capability,
                        intent_id,
                        phase,
                        json.dumps(payload, sort_keys=True) if payload is not None else None,
                        json.dumps(metadata or {}, sort_keys=True),
                        priority,
                        deadline_at,
                        at,
                        at,
                    ),
                )
                if self.audit is not None and audit_event:
                    self.audit.append(conn, audit_event, work_id, audit_detail or {}, at)
        except sqlite3.IntegrityError:
            # The two unique keys are the idempotency and identity guards.
            # Leave unrelated SQLite errors visible to the caller.
            if self.get(work_id, kind) is not None or self.find_by_key(kind, idempotency_key) is not None:
                return False
            raise
        return True

    def count_active(self, kind: str | None = None) -> int:
        if kind is None:
            row = self.db.read_one("SELECT COUNT(*) AS n FROM work_items WHERE state IN ('queued', 'running')")
        else:
            row = self.db.read_one(
                "SELECT COUNT(*) AS n FROM work_items WHERE kind = ? AND state IN ('queued', 'running')",
                (kind,),
            )
        return int(row["n"]) if row is not None else 0

    def transition(
        self,
        work_id: str,
        kind: str,
        expected_states: set[str] | frozenset[str],
        state: str,
        at: str,
        *,
        expected_phases: set[str | None] | frozenset[str | None] | None = None,
        phase: str | None | object = _UNSET,
        result: Any = _UNSET,
        error: Any = _UNSET,
        lease_until: str | None | object = _UNSET,
        metadata_patch: dict[str, Any] | None = None,
        assigned_to: str | None | object = _UNSET,
        fence: int | None | object = _UNSET,
        dispatched_at: str | None | object = _UNSET,
        audit_event: str | None = None,
        audit_detail: dict[str, Any] | None = None,
    ) -> bool:
        if not expected_states:
            return False
        with self.db.write() as conn:
            row = conn.execute(
                "SELECT * FROM work_items WHERE work_id = ? AND kind = ?",
                (work_id, kind),
            ).fetchone()
            if row is None or row["state"] not in expected_states:
                return False
            if expected_phases is not None and row["phase"] not in expected_phases:
                return False

            assignments = ["state = ?", "updated_at = ?"]
            values: list[Any] = [state, at]
            for column, value in (
                ("phase", phase),
                ("result_json", result),
                ("error_json", error),
                ("lease_until", lease_until),
                ("assigned_to", assigned_to),
                ("fence", fence),
                ("dispatched_at", dispatched_at),
            ):
                if value is _UNSET:
                    continue
                assignments.append(f"{column} = ?")
                values.append(json.dumps(value, sort_keys=True) if column.endswith("_json") and value is not None else value)

            metadata = json.loads(row["metadata_json"] or "{}")
            if metadata_patch:
                metadata.update(metadata_patch)
                assignments.append("metadata_json = ?")
                values.append(json.dumps(metadata, sort_keys=True))

            cursor = conn.execute(
                f"UPDATE work_items SET {', '.join(assignments)} WHERE work_id = ? AND kind = ? AND state = ?",
                (*values, work_id, kind, row["state"]),
            )
            if cursor.rowcount and self.audit is not None and audit_event:
                self.audit.append(
                    conn,
                    audit_event,
                    work_id,
                    {"kind": kind, "from": row["state"], "to": state, **(audit_detail or {})},
                    at,
                )
            return cursor.rowcount > 0

    def active(self, kind: str, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.db.read(
            "SELECT * FROM work_items WHERE kind = ? AND state IN ('queued', 'running') "
            "ORDER BY priority DESC, created_at LIMIT ?",
            (kind, limit),
        )
        return [_row_to_work_item(row) for row in rows]

    def for_assignee(self, kind: str, assigned_to: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.read(
            "SELECT * FROM work_items WHERE kind = ? AND assigned_to = ? ORDER BY updated_at DESC LIMIT ?",
            (kind, assigned_to, limit),
        )
        return [_row_to_work_item(row) for row in rows]

    def counts(self, kind: str) -> dict[str, int]:
        return {
            row["state"]: int(row["n"])
            for row in self.db.read(
                "SELECT state, COUNT(*) AS n FROM work_items WHERE kind = ? GROUP BY state",
                (kind,),
            )
        }

    def expire_stale_intents(self, now_stamp: str) -> list[str]:
        rows = self.db.read(
            "SELECT work_id FROM work_items WHERE kind = 'intent' AND state = 'running' "
            "AND lease_until IS NOT NULL AND lease_until < ?",
            (now_stamp,),
        )
        expired: list[str] = []
        for row in rows:
            key = row["work_id"]
            if self.transition(
                key,
                "intent",
                {"running"},
                "failed",
                now_stamp,
                error={"code": "lease.expired", "detail": "Task lease expired (process restart) before completion."},
                phase="lease_expired",
                audit_event="task.lease_expired",
            ):
                expired.append(key.removeprefix("intent:"))
        return expired
