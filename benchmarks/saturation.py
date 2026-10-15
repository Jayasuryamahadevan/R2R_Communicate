"""Local ASGI admission experiment with 48 concurrent slow intent requests.

This deliberately measures isolation/load shedding, not TCP/TLS or throughput.
The same signed workload reaches both checkouts. A 250 ms timer releases the
adapter after a heartbeat probe starts; report whether it answered before that.
Requires test extras. Compare: python -m benchmarks.saturation --baseline PATH
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from starlette.testclient import TestClient

from fasp_harness.core import DefaultSafeAdapter, FaspHarness
from fasp_harness.transport.http_app import create_app


class HeldAdapter(DefaultSafeAdapter):
    def __init__(self):
        self.release = threading.Event()

    def capabilities(self):
        return [{"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 3, "network": "none"}]

    def handle(self, intent):
        self.release.wait(5)
        return super().handle(intent)


def run() -> dict:
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        adapter = HeldAdapter()
        alice = FaspHarness(root / "a", "a", "http://a")
        bob = FaspHarness(root / "b", "b", "http://b", adapter=adapter, rate_limit_burst=10000)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
        try:
            with TestClient(create_app(bob)) as client, ThreadPoolExecutor(max_workers=50) as pool:
                client.post("/fasp/v1/envelopes", json=alice.make_envelope("heartbeat", bob.identity.system_id, {})).raise_for_status()
                requests = []
                for i in range(48):
                    envelope = alice.make_envelope(
                        "intent.propose",
                        bob.identity.system_id,
                        {
                            "intent_id": f"pressure-{i}",
                            "idempotency_key": f"pressure-{i}",
                            "capability": "observe.system.status.v1",
                            "risk": "observe",
                        },
                    )
                    requests.append(pool.submit(client.post, "/fasp/v1/envelopes", json=envelope))
                try:
                    deadline = time.monotonic() + 2
                    while True:
                        admitted = bob.db.read_one("SELECT COUNT(*) AS n FROM envelopes_inbox WHERE kind='intent.propose'")["n"]
                        finished = sum(f.done() for f in requests)
                        if admitted + finished >= 40:
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Pressure did not reach the intended handler/overload state")
                        time.sleep(0.005)
                    heartbeat = alice.make_envelope("heartbeat", bob.identity.system_id, {})
                    release = threading.Timer(0.25, adapter.release.set)
                    release.start()
                    started = time.perf_counter()
                    response = client.post("/fasp/v1/envelopes", json=heartbeat)
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    before_release = not adapter.release.is_set()
                    response.raise_for_status()
                finally:
                    adapter.release.set()
                    if "release" in locals():
                        release.cancel()
                statuses = [future.result(5).status_code for future in requests]
                if any(status not in {200, 503} for status in statuses):
                    raise RuntimeError(f"Unexpected pressure responses: {statuses}")
            import fasp_harness

            source_root = Path(fasp_harness.__file__).parent.parent
            digest = hashlib.sha256()
            for path in sorted((source_root / "fasp_harness").rglob("*.py")):
                digest.update(str(path.relative_to(source_root)).encode())
                digest.update(path.read_bytes())
            return {
                "scope": __doc__,
                "python": platform.python_version(),
                "platform": platform.platform(),
                "source_sha256": digest.hexdigest(),
                "work_requests": 48,
                "held_work_admitted_at_probe": admitted,
                "completed_work_at_probe": finished,
                "heartbeat_ms": elapsed_ms,
                "heartbeat_before_adapter_release": before_release,
                "accepted_work": statuses.count(200),
                "overloaded_work": statuses.count(503),
                "release_delay_ms": 250,
            }
        finally:
            adapter.release.set()
            alice.close()
            bob.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("--runs must be 1..10")
    if args.baseline is None:
        print(json.dumps(run(), indent=2))
        return
    sources = {"baseline": args.baseline.resolve(), "candidate": Path(__file__).parents[1]}
    result = {"baseline": [], "candidate": []}
    script = f"import runpy;runpy.run_path({str(Path(__file__).resolve())!r},run_name='__main__')"
    for iteration in range(args.runs):
        for name in sources if iteration % 2 == 0 else reversed(sources):
            child = subprocess.run(
                [sys.executable, "-c", script], cwd=sources[name], capture_output=True, text=True, timeout=20, check=True
            )
            result[name].append(json.loads(child.stdout))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
