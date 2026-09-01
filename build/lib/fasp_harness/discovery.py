"""Explicit, low-impact active discovery for a user-authorized local CIDR."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
from pathlib import Path
from urllib.request import urlopen

from .core import FaspHarness, JsonState, stamp


def probe(address: str, port: int, timeout: float) -> dict | None:
    url = f"http://{address}:{port}/.well-known/fasp/id-card.json"
    try:
        with urlopen(url, timeout=timeout) as response:  # nosec B310: explicitly user-authorized CIDR and fixed FASP path
            if response.status != 200:
                return None
            card = json.loads(response.read(64 * 1024 + 1))
        FaspHarness.verify_id_card(card)
        return {"address": address, "port": port, "card": card, "discovered_at": stamp()}
    except Exception:  # Probe failures are expected on unused local addresses.
        return None


def discover(cidr: str, port: int, timeout: float, workers: int, state_dir: Path, allow_large: bool = False) -> list[dict]:
    network = ipaddress.ip_network(cidr, strict=False)
    targets = list(network.hosts())
    if len(targets) > 1024 and not allow_large:
        raise ValueError("Refusing to scan more than 1024 hosts; use a narrower CIDR or --allow-large.")
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max(workers, 1), 32)) as pool:
        futures = [pool.submit(probe, str(host), port, timeout) for host in targets]
        for future in concurrent.futures.as_completed(futures):
            if result := future.result():
                results.append(result)
    state = JsonState(state_dir)
    known = state.get("discovered.json", {})
    for result in results:
        known[result["card"]["system_id"]] = result
    state.put("discovered.json", known)
    return sorted(results, key=lambda item: item["card"]["display_name"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover FASP ID cards on an explicitly authorized local network.")
    parser.add_argument("--cidr", required=True, help="Only this CIDR is probed; example: 192.168.0.0/24")
    parser.add_argument("--port", type=int, default=8766, help="Only this FASP HTTP port is probed.")
    parser.add_argument("--timeout", type=float, default=0.35)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--state-dir", type=Path, default=Path(".fasp"))
    parser.add_argument("--allow-large", action="store_true")
    args = parser.parse_args()
    found = discover(args.cidr, args.port, args.timeout, args.workers, args.state_dir, args.allow_large)
    print(json.dumps(found, indent=2))
    print(f"Found {len(found)} self-signed ID card(s). Discovery does not pair or grant authority.")


if __name__ == "__main__":
    main()
