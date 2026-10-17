"""Check retained replay and a new packet after restarting Bob."""

from __future__ import annotations

import json
from pathlib import Path

from container_live_stream_client import CAPABILITY, STATE, http, sample

from fasp_harness.core import FaspHarness
from fasp_harness.crypto.envelope import unb64
from fasp_harness.streaming import packetize

root = Path("/test")
result = json.loads((root / "client.json").read_text())
bob_id = json.loads((root / "reg-a.json").read_text())["peer_id"]
grant = json.loads((root / "observer-grant.json").read_text())
alice = FaspHarness(STATE, "Alice", "http://fasp-a:8766")
observer = FaspHarness(STATE / "observer", "Observer", "http://fasp-a:8766")
try:
    reading = sample()
    raw = json.dumps(reading, separators=(",", ":")).encode()
    packet = next(packetize(result["latest_stream_id"], 0, 3, raw, "application/json", 1024))
    packet["capability"] = CAPABILITY
    status, ack, _ = http(alice.make_envelope("stream.packet", bob_id, packet))
    assert status == 200 and ack["type"] == "stream.ack" and ack["ack_sequence"] == 3, (status, ack)

    status, replay, _ = http(observer.make_envelope("stream.pull", bob_id, {
        "capability": CAPABILITY,
        "stream_id": result["latest_stream_id"],
        "after_sequence": -1,
        "grant": {"id": grant["grant_id"], "digest": grant["digest"]},
    }))
    assert status == 200 and [packet["sequence"] for packet in replay["packets"]] == [0, 2, 3], (status, replay)
    expected = [entry["reading"] for entry in result["latest_readings"]] + [reading]
    assert [json.loads(unb64(packet["payload"])) for packet in replay["packets"]] == expected
    print("PASS Bob accepted latest packet 3 after restart; observer replayed exact packets 0, 2, 3")
finally:
    observer.close()
    alice.close()
