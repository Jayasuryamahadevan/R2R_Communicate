-- Preserve the complete, accepted stream contract so every packet, pull,
-- subscriber, and forwarding decision is checked against the same bounds.
ALTER TABLE streams ADD COLUMN contract_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE streams ADD COLUMN expires_at TEXT;
ALTER TABLE streams ADD COLUMN last_packet_at TEXT;
