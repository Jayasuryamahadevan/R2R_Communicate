"""Alternate fresh-process runs of two checkouts on the same host.

python -m benchmarks.compare --baseline /tmp/fasp-baseline --runs 5 --iterations 3000
Outputs raw per-run summaries, medians, and fresh-process peak RSS/import cost.
No result is a network, NATS comparison, physical-safety, or power-loss claim.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
from pathlib import Path


def command(source: Path, args: list[str]) -> dict:
    result = subprocess.run([sys.executable, *args], cwd=source, capture_output=True, text=True, check=True, timeout=120)
    return json.loads(result.stdout)


def footprint(source: Path, mode: str) -> dict:
    script = """
import contextlib, io, json, resource, sys, tempfile, time
from pathlib import Path
started = time.perf_counter()
mode = sys.argv[1]
if mode == 'package':
    import fasp_harness
elif mode == 'help':
    from fasp_harness.__main__ import main
    sys.argv = ['fasp', '--help']
    with contextlib.redirect_stdout(io.StringIO()):
        main()
elif mode == 'node':
    from fasp_harness.core import FaspHarness
    with tempfile.TemporaryDirectory() as directory:
        h = FaspHarness(Path(directory), 'footprint', 'http://127.0.0.1')
        h.close()
elapsed = (time.perf_counter() - started) * 1000
print(json.dumps({'startup_ms': elapsed, 'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                  'loaded_modules': len(sys.modules)}))
"""
    return command(source, ["-c", script, mode])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=3000)
    parser.add_argument("--channel", action="store_true", help="Also run 1000 TLS/mTLS WebSocket round trips per mode and checkout")
    args = parser.parse_args()
    if not 1 <= args.runs <= 20 or not 10 <= args.iterations <= 5000:
        parser.error("Expected 1..20 runs and 10..5000 iterations")
    sources = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    result = {"scope": "alternating local CPU/SQLite benchmarks and fresh-process Linux peak RSS; no broker or network",
              "platform": platform.platform(), "python": platform.python_version(), "runs": {name: [] for name in sources}, "footprint": {name: {} for name in sources}}
    if args.channel:
        result["scope"] += "; separate persistent loopback TLS/mTLS RTT runs included"
        result["channel"] = {name: [] for name in sources}
    for run in range(args.runs):
        for name in (sources if run % 2 == 0 else reversed(sources)):
            result["runs"][name].append(command(sources[name], ["-m", "benchmarks.protocol", "--iterations", str(args.iterations)]))
            if args.channel:
                script = "import runpy,sys;sys.argv=['channel.py','--iterations','1000'];runpy.run_path(" + repr(str(Path(__file__).with_name("channel.py").resolve())) + ",run_name='__main__')"
                result["channel"][name].append(command(sources[name], ["-c", script]))
            for mode in ("package", "help", "node"):
                result["footprint"][name].setdefault(mode, []).append(footprint(sources[name], mode))
    result["median"] = {}
    for name, runs in result["runs"].items():
        result["median"][name] = {
            key: {percentile: statistics.median(run["timings"][key][percentile] for run in runs) for percentile in ("p50", "p95", "p99")}
            for key in runs[0]["timings"]
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
