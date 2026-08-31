"""Property test for FASP fleet reservations (FASP_TWO_ROBOT_PROFILE.md):
however randomly a sequence of reservation requests interleaves, no two
currently-granted reservations may ever hold overlapping (cell, interval)
segments. This is exactly the class of bug (off-by-one at half-open-
interval boundaries, a stale row left behind by a renewal) that a handful
of hand-picked examples reliably miss."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from fasp_harness.core import FaspHarness

_cells = st.sampled_from(["a", "b", "c"])
_request = st.fixed_dictionaries({
    "cell": _cells,
    "start_offset_ms": st.integers(min_value=0, max_value=60_000),
    "duration_ms": st.integers(min_value=1_000, max_value=20_000),
})


def _granted_segments_overlap(harness: FaspHarness) -> bool:
    rows = harness.db.read(
        "SELECT reservation_segments.cell, reservation_segments.start_ms, reservation_segments.end_ms "
        "FROM reservation_segments JOIN reservations ON reservations.reservation_id = reservation_segments.reservation_id "
        "WHERE reservations.state = 'granted'"
    )
    by_cell: dict[str, list[tuple[int, int]]] = {}
    for row in rows:
        by_cell.setdefault(row["cell"], []).append((row["start_ms"], row["end_ms"]))
    for intervals in by_cell.values():
        intervals.sort()
        for (_, first_end), (second_start, _) in zip(intervals, intervals[1:], strict=False):
            if second_start < first_end:
                return True
    return False


class ReservationPropertyTests(unittest.TestCase):
    @given(st.lists(_request, min_size=1, max_size=20))
    @settings(max_examples=50, deadline=None)
    def test_no_two_granted_reservations_ever_overlap(self, requests: list[dict]) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            harness = FaspHarness(Path(temp_dir) / "robot", "robot", "http://robot:8766")
            now_ms = int(time.time() * 1000)
            for index, request in enumerate(requests):
                start = now_ms + request["start_offset_ms"]
                end = start + request["duration_ms"]
                payload = {
                    "reservation_id": f"res-{index}",
                    "lease_ms": min(120_000, request["duration_ms"] + 5_000),
                    "segments": [{"cell": request["cell"], "start_ms": start, "end_ms": end}],
                }
                harness.reservations.request(f"robot-{index}", payload)
                self.assertFalse(_granted_segments_overlap(harness), f"overlap detected after request {index}: {payload}")


if __name__ == "__main__":
    unittest.main()
