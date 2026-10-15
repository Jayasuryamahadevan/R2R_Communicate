"""Reproducible local protocol microbenchmark; not a network or hardware SLO.

Run: python -m benchmarks.protocol --iterations 200 --payload-bytes 256
Writes JSON to stdout. Temporary keys and state are deleted after the run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import tempfile
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any

from fasp_harness.core import FaspError, FaspHarness
from fasp_harness.crypto.canonical import canonicalize
from fasp_harness.crypto.envelope import sign, unsigned, verify
from fasp_harness.transport.canonical import decode_object


def measure(operation, iterations: int) -> dict[str, Any]:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    samples.sort()
    return {
        "samples": len(samples), "unit": "ms", "mean": statistics.mean(samples),
        "p50": samples[math.ceil(len(samples) * 0.50) - 1],
        "p95": samples[math.ceil(len(samples) * 0.95) - 1],
        "p99": samples[math.ceil(len(samples) * 0.99) - 1],
    }


def run(iterations: int, payload_bytes: int) -> dict[str, Any]:
    if not 10 <= iterations <= 5000 or not 0 <= payload_bytes <= 16384:
        raise ValueError("Expected 10..5000 iterations and 0..16384 payload bytes.")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        alice = FaspHarness(root / "alice", "alice", "http://local-alice")
        bob = FaspHarness(root / "bob", "bob", "http://local-bob", rate_limit_burst=iterations * 6 + 100)
        try:
            hello = bob.hello(alice.id_card())
            bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
            payload = {"padding": "x" * payload_bytes, "sensor_value": 0.125}
            envelopes = [alice.make_envelope("heartbeat", bob.identity.system_id, payload) for _ in range(iterations)]
            wire = canonicalize(envelopes[0])
            # Warm imports, cryptographic backend, and SQLite pages.
            bob.accept(alice.make_envelope("heartbeat", bob.identity.system_id, {}))
            timings = {
                "decode": measure(lambda: decode_object(wire), iterations),
                "canonicalize_unsigned": measure(lambda: canonicalize(unsigned(envelopes[0])), iterations),
                "sign": measure(lambda: sign(unsigned(envelopes[0]), alice.identity.private, alice.identity.kid), iterations),
                "verify": measure(lambda: verify(envelopes[0], alice.identity.public_b64), iterations),
            }
            sequence = iter(envelopes)
            timings["accept_fresh_heartbeat_with_sqlite"] = measure(lambda: bob.accept(next(sequence)), iterations)
            timings["accept_duplicate_heartbeat_with_sqlite"] = measure(lambda: bob.accept(envelopes[0]), iterations)
            bad = {**envelopes[0], "payload": {"tampered": True}}

            def reject() -> None:
                try:
                    bob.accept(bad)
                except FaspError as error:
                    if error.code == "auth.invalid_signature":
                        return
                    raise
                raise AssertionError("Tampered record accepted")

            timings["reject_tampered_signature"] = measure(reject, iterations)
            sources = sorted((Path(__file__).parents[1] / "fasp_harness").rglob("*.py"))
            digest = hashlib.sha256()
            for source in sources:
                digest.update(str(source.relative_to(Path(__file__).parents[1])).encode())
                digest.update(source.read_bytes())
            return {
                "scope": "single-process local CPU/SQLite microbenchmark; no network, TLS, robot, or external adapter",
                "environment": {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
                                "cryptography": version("cryptography"), "rfc8785": version("rfc8785"), "sqlite": bob.db.read_one("SELECT sqlite_version() AS v")["v"]},
                "source_sha256": digest.hexdigest(), "iterations": iterations, "payload_padding_bytes": payload_bytes,
                "encoded_envelope_bytes": len(wire), "sqlite_synchronous": "NORMAL", "timings": timings,
            }
        finally:
            alice.close()
            bob.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--payload-bytes", type=int, default=256)
    args = parser.parse_args()
    print(json.dumps(run(args.iterations, args.payload_bytes), indent=2))


if __name__ == "__main__":
    main()
