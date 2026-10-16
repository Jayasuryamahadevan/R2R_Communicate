-- An interrupted external effect cannot be called failed merely because its
-- local process died. Keep it durable and require authoritative reconciliation.
CREATE TABLE work_items_next (
    work_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (length(kind) > 0),
    owner TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    capability TEXT,
    intent_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'unknown')),
    phase TEXT,
    payload_json TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    error_json TEXT,
    lease_until TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    assigned_to TEXT,
    fence INTEGER,
    dispatched_at TEXT,
    deadline_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (kind, idempotency_key)
);
INSERT INTO work_items_next SELECT
    work_id, kind, owner, idempotency_key, capability, intent_id,
    CASE WHEN kind = 'intent' AND phase = 'lease_expired' THEN 'unknown' ELSE state END,
    phase, payload_json, metadata_json, result_json,
    CASE WHEN kind = 'intent' AND phase = 'lease_expired'
         THEN json_object('code', 'task.outcome_unknown', 'detail', 'Execution was interrupted; verify the external operation before retrying.')
         ELSE error_json END,
    lease_until, priority, assigned_to, fence, dispatched_at, deadline_at,
    created_at, updated_at
FROM work_items;
DROP TABLE work_items;
ALTER TABLE work_items_next RENAME TO work_items;
CREATE INDEX idx_work_items_kind_state_order ON work_items (kind, state, priority DESC, created_at);
CREATE INDEX idx_work_items_kind_assignee ON work_items (kind, assigned_to, updated_at);
CREATE INDEX idx_work_items_intent_lease ON work_items (kind, state, lease_until);
