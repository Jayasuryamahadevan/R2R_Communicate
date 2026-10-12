-- Per-peer read grants allow content-addressed deduplication without making
-- knowledge of an artifact_id an authorization credential.
CREATE TABLE artifact_access (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    peer_id TEXT NOT NULL,
    PRIMARY KEY (artifact_id, peer_id)
);
CREATE INDEX idx_artifact_access_peer ON artifact_access (peer_id, artifact_id);
INSERT INTO artifact_access (artifact_id, peer_id)
SELECT artifact_id, created_by FROM artifacts;
