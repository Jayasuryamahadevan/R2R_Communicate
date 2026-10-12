"""Repeatable local microbenchmark for the canonical packet and stream paths.

Run from the repository root with ``python benchmarks/canonical.py``. This
measures CPU-side normalization and packetization only, not network or radio.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fasp_harness.crypto.canonical import canonicalize  # noqa: E402
from fasp_harness.streaming import MAX_PACKET_BYTES, packetize  # noqa: E402
from fasp_harness.transport.canonical import decode_object  # noqa: E402


def timed(action, repetitions: int, rounds: int = 5) -> float:
    samples: list[float] = []
    for _ in range(rounds):
        started = time.perf_counter()
        for _ in range(repetitions):
            action()
        samples.append(time.perf_counter() - started)
    return statistics.median(samples)


def main() -> None:
    packet = json.dumps({"fasp": "fasp/1", "kind": "heartbeat", "payload": {"observation": "x" * 900}}, separators=(",", ":")).encode()
    frame = b"x" * (1024 * 1024)

    def normalize() -> None:
        canonicalize(decode_object(packet))

    def stream() -> None:
        for _ in packetize("bench-stream", 0, 0, frame, "application/octet-stream", MAX_PACKET_BYTES):
            pass

    normalize()
    stream()
    normalize_count = 5000
    stream_count = 40
    normalize_seconds = timed(normalize, normalize_count)
    stream_seconds = timed(stream, stream_count)
    result = {
        "benchmark": "local canonical normalization and packetization",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packet_bytes": len(packet),
        "normalize_packets_per_second": round(normalize_count / normalize_seconds),
        "frame_bytes": len(frame),
        "packet_payload_limit_bytes": MAX_PACKET_BYTES,
        "packetize_mib_per_second": round(stream_count / stream_seconds, 2),
        "rounds": 5,
        "method": "median wall time; no network, signature, database, or adapter work",
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
