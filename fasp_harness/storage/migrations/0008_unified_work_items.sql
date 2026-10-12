-- One durable record and lifecycle for all executable work. Intent tasks
-- and fleet missions differ in payload and metadata, not in their core
-- queued/running/terminal state model.
CREATE TABLE work_items (
    work_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (length(kind) > 0),
    owner TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    capability TEXT,
    intent_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
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
CREATE INDEX idx_work_items_kind_state_order ON work_items (kind, state, priority DESC, created_at);
CREATE INDEX idx_work_items_kind_assignee ON work_items (kind, assigned_to, updated_at);
CREATE INDEX idx_work_items_intent_lease ON work_items (kind, state, lease_until);

-- Preserve intent outcomes and idempotency keys while collapsing the old
-- task-specific lifecycle into the shared work-item states.
INSERT INTO work_items (
    work_id, kind, owner, idempotency_key, capability, intent_id, state,
    phase, result_json, error_json, lease_until, created_at, updated_at
)
SELECT
    'intent:' || idempotency_key,
    'intent',
    from_peer,
    idempotency_key,
    capability,
    intent_id,
    CASE state
        WHEN 'PROPOSED' THEN 'queued'
        WHEN 'RUNNING' THEN 'running'
        WHEN 'CANCEL_PENDING' THEN 'running'
        WHEN 'COMPLETED' THEN 'succeeded'
        WHEN 'CANCELLED' THEN 'cancelled'
        ELSE 'failed'
    END,
    CASE state
        WHEN 'REJECTED' THEN 'rejected'
        WHEN 'CANCEL_PENDING' THEN 'cancel_requested'
        ELSE NULL
    END,
    result_json,
    error_json,
    lease_until,
    created_at,
    updated_at
FROM tasks;

-- Preserve the fleet definition and coordination metadata in the same
-- generic record. Mission phases remain descriptive; lifecycle status is
-- shared with every other kind of work.
INSERT INTO work_items (
    work_id, kind, owner, idempotency_key, state, phase, payload_json,
    metadata_json, result_json, error_json, priority, assigned_to, fence,
    dispatched_at, deadline_at, created_at, updated_at
)
SELECT
    'mission:' || mission_id,
    'mission',
    requested_by,
    mission_id,
    CASE
        WHEN state IN ('ACCEPTED', 'PREFLIGHT') THEN 'queued'
        WHEN state IN ('ASSIGNED', 'RUNNING', 'PAUSED') THEN 'running'
        WHEN state = 'COMPLETED' THEN 'succeeded'
        WHEN state = 'CANCELLED' THEN 'cancelled'
        ELSE 'failed'
    END,
    lower(state),
    definition_json,
    json_object('fleet', fleet, 'vehicle_id', vehicle_id, 'preflight', json(preflight_json)),
    result_json,
    error_json,
    priority,
    vehicle_id,
    fence,
    dispatched_at,
    deadline_at,
    created_at,
    updated_at
FROM missions;

DROP TABLE tasks;
DROP TABLE missions;
