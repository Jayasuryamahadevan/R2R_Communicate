"""Explicit, low-impact active discovery for a user-authorized local CIDR."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import math
import ssl
from pathlib import Path
from urllib import request

from .core import FaspHarness, JsonState, stamp
from .transport.canonical import decode_object


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def probe(address: str, port: int, timeout: float, scheme: str = "http", ca_cert: str | None = None) -> dict | None:
    display_host = f"[{address}]" if ":" in address else address
    url = f"{scheme}://{display_host}:{port}/.well-known/fasp/id-card.json"
    try:
        handlers = [request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_cert))] if scheme == "https" else []
        opener = request.build_opener(*handlers, _NoRedirect())
        with opener.open(url, timeout=timeout) as response:  # nosec B310: explicitly user-authorized CIDR and fixed FASP path
            if response.status != 200:
                return None
            body = response.read(64 * 1024 + 1)
            if len(body) > 64 * 1024:
                return None
            card = decode_object(body)
        FaspHarness.verify_id_card(card)
        return {"address": address, "port": port, "card": card, "discovered_at": stamp()}
    except Exception:  # Probe failures are expected on unused local addresses.
        return None


def discover(cidr: str, port: int, timeout: float, workers: int, state_dir: Path, allow_large: bool = False, scheme: str = "http", ca_cert: str | None = None) -> list[dict]:
    if scheme not in {"http", "https"} or not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout <= 30 or not 1 <= workers <= 32:
        raise ValueError("Expected http(s), port 1..65535, timeout 0..30 seconds, and workers 1..32.")
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > 65536:
        raise ValueError("Refusing to scan more than 65,536 addresses; use a narrower CIDR.")
    targets = list(network.hosts())
    if len(targets) > 1024 and not allow_large:
        raise ValueError("Refusing to scan more than 1024 hosts; use a narrower CIDR or --allow-large.")
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max(workers, 1), 32)) as pool:
        futures = [pool.submit(probe, str(host), port, timeout, scheme, ca_cert) for host in targets]
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
    parser.add_argument("--scheme", choices=("http", "https"), default="http", help="Use HTTPS for a production Wi-Fi or Ethernet network.")
    parser.add_argument("--ca-cert", help="CA certificate bundle for HTTPS discovery.")
    parser.add_argument("--timeout", type=float, default=0.35)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--state-dir", type=Path, default=Path(".fasp"))
    parser.add_argument("--allow-large", action="store_true")
    args = parser.parse_args()
    found = discover(args.cidr, args.port, args.timeout, args.workers, args.state_dir, args.allow_large, args.scheme, args.ca_cert)
    print(json.dumps(found, indent=2))
    print(f"Found {len(found)} self-signed ID card(s). Discovery does not pair or grant authority.")


if __name__ == "__main__":
    main()
