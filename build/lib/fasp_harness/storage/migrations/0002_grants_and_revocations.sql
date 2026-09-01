-- Grants: time-limited, scoped delegated authority (FASP_PROTOCOL.md ss6,
-- ss8). A grant layers ON TOP OF a peer's pairing-time capability prefixes
-- -- it can narrow what an intent may do, but referencing one never widens
-- authority beyond what pairing already scoped (see policy/grants.py).
CREATE TABLE grants (
    grant_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject_peer TEXT NOT NULL,
    capability_prefixes_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    purpose TEXT,
    constraints_json TEXT,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX idx_grants_subject_peer ON grants (subject_peer);

-- Revocations: presence of a row means `peer_id` is currently revoked and
-- MUST be rejected regardless of its `peers.state` (ss12: "stop accepting
-- grants bound to that key ... require re-pairing"). Kept as a separate
-- table rather than a `peers.state` value so a later successful re-pairing
-- (FaspHarness.confirm_peer, which clears the row) doesn't need to erase
-- the fact that a revocation happened -- callers who need that history
-- can still see it via the audit chain added in a later phase.
CREATE TABLE revocations (
    peer_id TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    revocation_ref TEXT
);

-- ss3.3's pairing-record fields this reference harness didn't yet carry.
-- trust_tier is descriptive (matches the spec's own example value); the
-- new expires_at is enforced in FaspHarness._peer() -- a pairing is no
-- longer authority forever once confirmed.
ALTER TABLE peers ADD COLUMN trust_tier TEXT NOT NULL DEFAULT 'local-paired';
ALTER TABLE peers ADD COLUMN expires_at TEXT;
