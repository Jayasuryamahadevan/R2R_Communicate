"""Check a local production listener through its real TLS and mTLS path."""

from __future__ import annotations

import argparse
import http.client
import math
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit


def check_ready(
    public_url: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    *,
    connect_host: str = "127.0.0.1",
    connect_port: int = 8766,
    timeout: float = 3.0,
) -> bool:
    """Connect locally while verifying the advertised DNS name and client auth."""
    parsed = urlsplit(public_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("A production health check needs a valid HTTPS public URL.")
    server_name = parsed.hostname
    advertised_port = parsed.port
    if not server_name.isascii() or any(character in server_name for character in "\r\n"):
        raise ValueError("The advertised hostname must be an ASCII DNS name or IP address.")
    if not 1 <= connect_port <= 65535 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Connect port and timeout must be positive and finite.")

    context = ssl.create_default_context(cafile=str(ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(client_cert), str(client_key))
    with socket.create_connection((connect_host, connect_port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as connection:
            connection.settimeout(timeout)
            host_header = f"[{server_name}]" if ":" in server_name else server_name
            if advertised_port is not None:
                host_header += f":{advertised_port}"
            connection.sendall(f"GET /readyz HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode("ascii"))
            response = http.client.HTTPResponse(connection, method="GET")
            response.begin()
            return response.status == 200


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify local FASP readiness through TLS and client certificates.")
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--ca-cert", required=True, type=Path)
    parser.add_argument("--client-cert", required=True, type=Path)
    parser.add_argument("--client-key", required=True, type=Path)
    parser.add_argument("--connect-host", default="127.0.0.1")
    parser.add_argument("--connect-port", type=int, default=8766)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args(argv)
    try:
        ready = check_ready(
            args.public_url,
            args.ca_cert,
            args.client_cert,
            args.client_key,
            connect_host=args.connect_host,
            connect_port=args.connect_port,
            timeout=args.timeout,
        )
    except (http.client.HTTPException, OSError, ValueError) as exc:
        print(f"not ready: {type(exc).__name__}")
        return 1
    print("ready" if ready else "not ready: HTTP status is not 200")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
