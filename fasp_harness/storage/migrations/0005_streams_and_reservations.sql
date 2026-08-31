-- Live-stream control state and bounded packet retention
-- (FASP_MESSAGING_STREAMING.md). One row per stream; packets are a
-- separate table so retention pruning (bounding memory even against a
-- malicious sender) is a plain indexed DELETE instead of a Python
-- rewrite-the-whole-list operation.
CREATE TABLE streams (
    stream_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    delivery TEXT NOT NULL CHECK (delivery IN ('reliable', 'latest')),
    content_type TEXT NOT NULL,
    max_payload_bytes INTEGER NOT NULL,
    window INTEGER NOT NULL,
    retention_packets INTEGER NOT NULL,
    next_expected INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL,
    opened_at_monotonic_ns INTEGER NOT NULL,
    closed_at_monotonic_ns INTEGER,
    closed_reason TEXT
);

CREATE TABLE stream_packets (
    stream_id TEXT NOT NULL REFERENCES streams (stream_id),
    sequence INTEGER NOT NULL,
    packet_json TEXT NOT NULL,
    PRIMARY KEY (stream_id, sequence)
);

-- Fleet space-time reservations (FASP_TWO_ROBOT_PROFILE.md), normalized so
-- the overlap check (previously an O(active reservations * segments *
-- proposed segments) Python triple loop) becomes an indexed range scan
-- per proposed segment instead.
CREATE TABLE reservations (
    reservation_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('granted', 'released')),
    lease_until_ms INTEGER NOT NULL
);

CREATE TABLE reservation_segments (
    reservation_id TEXT NOT NULL REFERENCES reservations (reservation_id),
    cell TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL
);
CREATE INDEX idx_reservation_segments_cell_range ON reservation_segments (cell, start_ms, end_ms);
