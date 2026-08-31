-- Extend `tasks` into the full PROPOSED/ACCEPTED/RUNNING/CANCEL_PENDING/
-- COMPLETED/FAILED/CANCELLED/REJECTED state machine (ss7.2). "ACCEPTED" is
-- a transient in-code step this reference harness folds directly into the
-- RUNNING transition (see policy note in core.py's _handle_intent) rather
-- than a separately observable row state.
--
-- SQLite's ALTER TABLE can't add a NOT NULL column without a default or
-- change an existing column's nullability, so this rebuilds the table.
CREATE TABLE tasks_new (
    idempotency_key TEXT PRIMARY KEY,
    intent_id TEXT,
    capability TEXT NOT NULL,
    from_peer TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PROPOSED', 'RUNNING', 'CANCEL_PENDING', 'COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED')),
    result_json TEXT,
    error_json TEXT,
    lease_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT INTO tasks_new (idempotency_key, intent_id, capability, from_peer, state, result_json, error_json, lease_until, created_at, updated_at)
SELECT
    idempotency_key, intent_id, capability, from_peer,
    CASE WHEN json_extract(result_json, '$.type') = 'task.fail' THEN 'FAILED' ELSE 'COMPLETED' END,
    result_json,
    NULL,
    NULL,
    created_at,
    created_at
FROM tasks;
DROP TABLE tasks;
ALTER TABLE tasks_new RENAME TO tasks;
CREATE INDEX idx_tasks_state_lease ON tasks (state, lease_until);

-- Tamper-evident, hash-chained append-only audit trail (ss11) of grant
-- decisions, task-lifecycle transitions, and revocation/pairing events.
-- Appended in the SAME transaction as the state change it documents (see
-- fasp_harness/audit/chain.py) so "it happened" and "it's audited" are
-- atomic. detail_json is deliberately minimal -- ids, decisions, digests,
-- never intent payload contents or raw sensor data.
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
