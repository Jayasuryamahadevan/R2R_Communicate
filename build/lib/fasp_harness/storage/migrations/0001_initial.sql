-- Peers: pairing state for a known counterpart system
-- (FASP_PROTOCOL.md ss3.3). Phase 3 adds trust_tier/revocation_ref/expires_at.
CREATE TABLE peers (
    peer_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    display_name TEXT,
    card_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'paired')),
    allowed_capability_prefixes_json TEXT NOT NULL,
    pair_code TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    paired_at TEXT
);

-- Envelopes inbox: append-only record of every accepted envelope, keyed by
-- its globally-unique message_id. The UNIQUE constraint on message_id IS
-- the replay-detection mechanism (ss5: "the receiver MUST retain a bounded
-- replay cache ... through expires_at") -- a second envelope with the same
-- message_id can never be inserted twice, so duplicate delivery is
-- detected by the database itself rather than a capped in-memory window
-- that silently forgets old entries. response_json is filled in once the
-- envelope has been processed, so a duplicate delivery returns the
-- original response instead of reprocessing (ss7.1's idempotent handling).
CREATE TABLE envelopes_inbox (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    conversation_id TEXT,
    causation_id TEXT,
    from_peer TEXT NOT NULL,
    kind TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    response_json TEXT
);
CREATE INDEX idx_envelopes_inbox_from_peer ON envelopes_inbox (from_peer, row_id);

-- Tasks: the idempotency journal for intent.propose (ss7.1). A duplicate
-- proposal of the same idempotency_key returns the existing row's result
-- instead of re-invoking the adapter ("MUST NOT repeat ... effect"), and
-- the PRIMARY KEY makes a concurrent duplicate race resolve to exactly one
-- winner. Phase 4 extends this into the full PROPOSED/ACCEPTED/RUNNING/...
-- state machine.
CREATE TABLE tasks (
    idempotency_key TEXT PRIMARY KEY,
    intent_id TEXT,
    capability TEXT NOT NULL,
    from_peer TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
