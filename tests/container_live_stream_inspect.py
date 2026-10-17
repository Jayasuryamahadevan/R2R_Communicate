"""Verify the receiver's retained wire packets against Alice's live readings."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fasp_harness.crypto.envelope import unb64
from fasp_harness.streaming import digest

result = json.loads(Path("/test/client.json").read_text())
database = sqlite3.connect("/home/fasp/.fasp/fasp.db")
database.row_factory = sqlite3.Row

for stream_name, expected in (
    ("reliable", list(enumerate(result["reliable_readings"]))),
    ("latest", [(entry["sequence"], entry["reading"]) for entry in result["latest_readings"]]),
):
    stream_id = result[f"{stream_name}_stream_id"]
    rows = database.execute(
        "SELECT sequence, packet_json FROM stream_packets WHERE stream_id = ? ORDER BY sequence",
        (stream_id,),
    ).fetchall()
    assert [row["sequence"] for row in rows] == [sequence for sequence, _ in expected], rows
    for row, (sequence, reading) in zip(rows, expected, strict=True):
        packet = json.loads(row["packet_json"])
        raw = unb64(packet["payload"])
        assert packet["sequence"] == sequence
        assert packet["checksum"] == digest(raw)
        assert json.loads(raw) == reading
    stream = database.execute("SELECT state, last_sequence FROM streams WHERE stream_id = ?", (stream_id,)).fetchone()
    assert stream["last_sequence"] == expected[-1][0]
    print(f"PASS Bob retained {len(rows)} exact {stream_name} packets; last sequence {stream['last_sequence']}; state {stream['state']}")

database.close()
