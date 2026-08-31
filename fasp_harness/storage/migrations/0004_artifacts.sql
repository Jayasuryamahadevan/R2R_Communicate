-- Immutable, content-addressed artifacts (FASP_PROTOCOL.md ss11). Large
-- results (bigger than comfortably fits in a signed, 64 KiB-capped inline
-- envelope, ss5) are stored here and referenced by digest instead.
CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retention_until TEXT,
    storage_path TEXT NOT NULL
);
