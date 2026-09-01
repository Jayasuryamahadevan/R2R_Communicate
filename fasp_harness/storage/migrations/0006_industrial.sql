-- Phase 8: the durable state the industrial layers need.
--
-- All five tables share one property worth stating once: they are
-- management-plane state. None of them is on a control path, none of them
-- is consulted inside a safety function, and a corrupted or unavailable
-- database here degrades coordination -- it can never degrade a protective
-- stop, because a protective stop does not consult this process at all.

-- Safety demands and clears, durably recorded. The supervisor keeps a
-- bounded in-memory window for reporting; this is the record that survives
-- a restart and feeds the audit chain and the safety case.
CREATE TABLE safety_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('demand', 'clear', 'observation', 'fault')),
    source TEXT NOT NULL,
    origin TEXT NOT NULL,
    reason TEXT NOT NULL,
    latched INTEGER NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX idx_safety_events_ts ON safety_events (ts);

-- Leader election for hot-standby edge deployments. `fence` is the point:
-- it increases on every change of holder and never decreases, so an old
-- leader that wakes up after a partition presents a stale fence and is
-- refused by anything that guards on it -- rather than issuing commands
-- alongside the new leader. (Lamport's fencing token; the same mechanism
-- Chubby/ZooKeeper expose as an epoch.)
CREATE TABLE leases (
    name TEXT PRIMARY KEY,
    holder TEXT NOT NULL,
    fence INTEGER NOT NULL,
    acquired_at TEXT NOT NULL,
    renewed_at TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    metadata_json TEXT
);

-- Store-and-forward outbox: the mechanism that makes an offline or
-- partitioned link a delay rather than a loss. Ordered per destination,
-- retried with capped exponential backoff, dead-lettered rather than
-- retried forever. `message_id` is UNIQUE so an enqueue is idempotent and
-- a duplicated send request cannot produce two deliveries.
CREATE TABLE outbox (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    destination TEXT NOT NULL,
    kind TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'inflight', 'sent', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms INTEGER NOT NULL,
    expires_at_ms INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_outbox_ready ON outbox (state, next_attempt_ms);
CREATE INDEX idx_outbox_destination ON outbox (destination, row_id);

-- Missions: Layer 3's unit of work. A mission is goal-level ("go to dock 7,
-- pick tote 42") and is dispatched to a vehicle's own autonomy stack, which
-- decides how to achieve it -- hence `definition_json` holding steps, not a
-- trajectory. `fence` records the leader lease that dispatched it, so a
-- mission from a superseded leader is identifiable after the fact.
CREATE TABLE missions (
    mission_id TEXT PRIMARY KEY,
    requested_by TEXT NOT NULL,
    fleet TEXT,
    vehicle_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('ACCEPTED', 'PREFLIGHT', 'ASSIGNED', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED')),
    priority INTEGER NOT NULL DEFAULT 0,
    definition_json TEXT NOT NULL,
    preflight_json TEXT,
    result_json TEXT,
    error_json TEXT,
    fence INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    dispatched_at TEXT,
    deadline_at TEXT
);
CREATE INDEX idx_missions_state ON missions (state, priority DESC, created_at);
CREATE INDEX idx_missions_vehicle ON missions (vehicle_id, updated_at);

-- Digital-twin divergence history: what the twin predicted, what the real
-- system reported, and how far apart they were. Kept because a twin that
-- is never compared against reality is a simulation, not a twin, and the
-- comparison is only meaningful as a trend.
CREATE TABLE twin_observations (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    predicted_json TEXT NOT NULL,
    divergence REAL NOT NULL,
    exceeded INTEGER NOT NULL
);
CREATE INDEX idx_twin_entity ON twin_observations (entity_id, row_id);
