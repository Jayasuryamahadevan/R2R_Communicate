-- Space-time reservations that survive contact with hardware.
--
-- The original overlap test was exact: `cell = ? AND start_ms < ? AND
-- end_ms > ?`. Exactness is the right property for a ledger and the wrong
-- one for two machines that do not agree about the time and do not know
-- precisely where they are. Two reservations ten milliseconds apart on
-- paper, held by owners whose clocks disagree by two hundred, are not
-- apart at all -- and the ledger said they were.
--
-- Two additions, both nullable so every existing reservation keeps its
-- exact semantics unchanged:
--
--   guard_start_ms / guard_end_ms -- the segment dilated by the requester's
--   own clock uncertainty plus its decision margin. Stored precomputed
--   rather than derived at query time so the overlap test stays a single
--   indexed range scan.
--
--   frame_id + the six bounds -- an axis-aligned volume already dilated by
--   the requester's guard band, so two robots can conflict physically
--   without having agreed a shared cell vocabulary first. A cell name is a
--   convention two vendors must share; a box in a named frame is not.
--
-- A segment may carry a cell, a volume, or both. Conflict is the union:
-- same cell, or overlapping volume in the same frame. Conservative by
-- construction, because a reservation system that misses a conflict is
-- worse than one that invents an occasional false one.

ALTER TABLE reservation_segments ADD COLUMN guard_start_ms INTEGER;
ALTER TABLE reservation_segments ADD COLUMN guard_end_ms INTEGER;
ALTER TABLE reservation_segments ADD COLUMN frame_id TEXT;
ALTER TABLE reservation_segments ADD COLUMN min_x REAL;
ALTER TABLE reservation_segments ADD COLUMN min_y REAL;
ALTER TABLE reservation_segments ADD COLUMN min_z REAL;
ALTER TABLE reservation_segments ADD COLUMN max_x REAL;
ALTER TABLE reservation_segments ADD COLUMN max_y REAL;
ALTER TABLE reservation_segments ADD COLUMN max_z REAL;

-- Rows written before this migration had no guard, which is exactly a
-- guard of zero. Backfilling rather than allowing NULL keeps the overlap
-- query free of COALESCE on an indexed column.
UPDATE reservation_segments SET guard_start_ms = start_ms, guard_end_ms = end_ms
WHERE guard_start_ms IS NULL;

CREATE INDEX idx_reservation_segments_guard_range ON reservation_segments (cell, guard_start_ms, guard_end_ms);
CREATE INDEX idx_reservation_segments_volume ON reservation_segments (frame_id, guard_start_ms, guard_end_ms);
