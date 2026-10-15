"""Compatibility adapter for intent tasks over the shared work-item store.

The public FASP task messages keep their established names. Persistence and
state changes live in :mod:`work_items_repo`, shared with fleet missions.
"""

from __future__ import annotations

from typing import Any

from ..audit.chain import AuditChain
from .db import Database
from .work_items_repo import WorkItemsRepo, WorkState

TERMINAL_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED", "REJECTED"})


class TasksRepo:
    def __init__(self, db: Database, audit: AuditChain, work_items: WorkItemsRepo | None = None) -> None:
        self.db = db
        self.audit = audit
        self.work_items = work_items or WorkItemsRepo(db, audit)

    @staticmethod
    def _work_id(idempotency_key: str) -> str:
        return f"intent:{idempotency_key}"

    def get(self, idempotency_key: str) -> dict[str, Any] | None:
        item = self.work_items.get(self._work_id(idempotency_key), "intent")
        if item is None:
            return None
        state = {
            WorkState.QUEUED.value: "PROPOSED",
            WorkState.RUNNING.value: "RUNNING",
            WorkState.SUCCEEDED.value: "COMPLETED",
            WorkState.FAILED.value: "FAILED",
            WorkState.CANCELLED.value: "CANCELLED",
        }[item["state"]]
        if item["phase"] == "rejected":
            state = "REJECTED"
        elif item["phase"] == "cancel_requested":
            state = "CANCEL_PENDING"
        return {
            "idempotency_key": item["idempotency_key"],
            "intent_id": item["intent_id"],
            "capability": item["capability"],
            "payload": item["payload"],
            "from_peer": item["owner"],
            "state": state,
            "result": item["result"],
            "error": item["error"],
            "lease_until": item["lease_until"],
            "created_at": item["created_at"],
            "updated_at": item["updated_at"],
        }

    def count_inflight(self) -> int:
        """Durable admission bound for intent execution."""
        return self.work_items.count_active("intent")

    def propose(self, idempotency_key: str, intent_id: str | None, capability: str, from_peer: str, at: str, payload: dict[str, Any] | None = None, *, max_active: int | None = None) -> bool:
        return self.work_items.create(
            work_id=self._work_id(idempotency_key),
            kind="intent",
            owner=from_peer,
            idempotency_key=idempotency_key,
            intent_id=intent_id,
            capability=capability,
            payload=payload,
            at=at,
            audit_event="task.proposed",
            audit_detail={"capability": capability, "from_peer": from_peer},
            max_active=max_active,
        )

    def reject(self, idempotency_key: str, error: dict[str, Any], at: str) -> bool:
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.QUEUED.value},
            WorkState.FAILED.value,
            at,
            phase="rejected",
            error=error,
            audit_event="task.rejected",
        )

    def start_running(self, idempotency_key: str, lease_until: str, at: str) -> bool:
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.QUEUED.value},
            WorkState.RUNNING.value,
            at,
            phase=None,
            lease_until=lease_until,
            audit_event="task.running",
        )

    def complete(self, idempotency_key: str, result: dict[str, Any], at: str) -> bool:
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.RUNNING.value},
            WorkState.SUCCEEDED.value,
            at,
            expected_phases={None, "cancel_requested"},
            phase=None,
            result=result,
            lease_until=None,
            audit_event="task.completed",
        )

    def fail(self, idempotency_key: str, error: dict[str, Any], at: str) -> bool:
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.RUNNING.value},
            WorkState.FAILED.value,
            at,
            expected_phases={None, "cancel_requested"},
            phase=None,
            error=error,
            lease_until=None,
            audit_event="task.failed",
        )

    def request_cancel(self, idempotency_key: str, at: str) -> bool:
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.RUNNING.value},
            WorkState.RUNNING.value,
            at,
            expected_phases={None},
            phase="cancel_requested",
            audit_event="task.cancel_requested",
        )

    def cancel_immediately(self, idempotency_key: str, at: str) -> bool:
        """Cancel queued work or a running task whose adapter accepted cancel."""
        if self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.QUEUED.value},
            WorkState.CANCELLED.value,
            at,
            audit_event="task.cancelled",
        ):
            return True
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.RUNNING.value},
            WorkState.CANCELLED.value,
            at,
            expected_phases={"cancel_requested"},
            phase=None,
            lease_until=None,
            audit_event="task.cancelled",
        )

    def resume_running(self, idempotency_key: str, at: str) -> bool:
        """Clear a declined cancellation request and keep the task running."""
        return self.work_items.transition(
            self._work_id(idempotency_key),
            "intent",
            {WorkState.RUNNING.value},
            WorkState.RUNNING.value,
            at,
            expected_phases={"cancel_requested"},
            phase=None,
            audit_event="task.cancel_declined",
        )

    def expire_stale_leases(self, now_stamp: str) -> list[str]:
        return self.work_items.expire_stale_intents(now_stamp)
