"""uvicorn ASGI server wiring: TLS/mTLS, CLI entry point.

Replaces the old `http.server.ThreadingHTTPServer` baseline. HTTP/1.1
parsing, chunked transfer-encoding, keep-alive, and TLS/ALPN negotiation
are exactly the class of code where a hand-rolled implementation is a
security-hardening *regression* next to an audited library -- this project
values a minimal dependency footprint, but that value doesn't extend to
reinventing a network protocol parser.
"""

from __future__ import annotations

import argparse
import importlib
import ssl
from pathlib import Path

import uvicorn

from ..core import FaspHarness
from ..protocol.errors import FaspError
from ..security.posture import DeploymentConfig, SecurityProfile, evaluate_posture
from .http_app import create_app, default_health
from .middleware import IPRateLimitMiddleware


def load_adapter(reference: str | None) -> object | None:
    """Load a local model adapter as module:object or module:factory."""
    if not reference:
        return None
    try:
        module_name, object_name = reference.split(":", 1)
        candidate = getattr(importlib.import_module(module_name), object_name)
        adapter = candidate() if callable(candidate) and not hasattr(candidate, "handle") else candidate
        if not callable(getattr(adapter, "capabilities", None)) or not callable(getattr(adapter, "handle", None)):
            raise TypeError("adapter must provide capabilities() and handle(intent)")
        return adapter
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise SystemExit(f"Cannot load --adapter {reference!r}: {exc}") from exc


def build_asgi_app(harness: FaspHarness, ip_rate_limit_per_second: float = 20.0, ip_rate_limit_burst: int = 40, health=None):
    return IPRateLimitMiddleware(create_app(harness, health), ip_rate_limit_per_second, ip_rate_limit_burst)


def _tls13_only_context_factory(config: uvicorn.Config, default_factory):
    context: ssl.SSLContext = default_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a model-agnostic FASP harness endpoint.")
    parser.add_argument("serve", nargs="?", default="serve")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--name", default="fasp-system")
    parser.add_argument("--state-dir", type=Path, default=Path(".fasp"))
    parser.add_argument("--public-url", help="Advertised HTTPS/HTTP base URL; required for a reachable LAN peer.")
    parser.add_argument("--adapter", help="Optional local model adapter: module:object or module:factory")
    parser.add_argument("--tls-cert", type=Path, help="PEM certificate for production HTTPS.")
    parser.add_argument("--tls-key", type=Path, help="PEM private key for production HTTPS.")
    parser.add_argument("--tls-client-ca", type=Path, help="PEM CA bundle to require and verify client certificates (mTLS). Transport hardening only -- never a substitute for envelope-level peer authorization.")
    parser.add_argument("--insecure-http", action="store_true", help="Allow plain HTTP for isolated development LANs only.")
    parser.add_argument("--rate-limit-per-peer", type=float, default=10.0, help="Sustained signed-envelope requests per second, per paired peer.")
    parser.add_argument("--rate-limit-burst", type=int, default=20, help="Burst allowance on top of --rate-limit-per-peer.")
    parser.add_argument("--ip-rate-limit-per-second", type=float, default=20.0, help="Sustained requests per second, per source address, before authentication.")
    parser.add_argument("--ip-rate-limit-burst", type=int, default=40)
    parser.add_argument("--config", type=Path, help="Node configuration JSON (see examples/node.json): safety controller, fleets, site map, HA. Without it this serves a plain coordination node.")
    parser.add_argument("--security-profile", choices=["development", "hardened", "production"], default="development", help="Startup gate. `production` refuses to run without mutual TLS, an enforcing ROS 2 domain, 0600 private material, and a real safety controller.")
    args = parser.parse_args()

    secure = bool(args.tls_cert or args.tls_key)
    if bool(args.tls_cert) != bool(args.tls_key):
        raise SystemExit("--tls-cert and --tls-key must be supplied together.")
    if args.tls_client_ca and not secure:
        raise SystemExit("--tls-client-ca requires --tls-cert/--tls-key.")
    if not secure and args.host not in {"127.0.0.1", "localhost", "::1"} and not args.insecure_http:
        raise SystemExit("Refusing plain HTTP on a non-loopback interface. Use TLS or explicitly pass --insecure-http for an isolated development LAN.")
    base_url = args.public_url or f"{'https' if secure else 'http'}://{args.host}:{args.port}"
    if secure and not base_url.startswith("https://"):
        raise SystemExit("A TLS listener requires an https:// --public-url.")

    # The security gate runs before anything binds a socket or connects to
    # a controller: a deployment that would be refused is refused before it
    # can do anything at all.
    profile = SecurityProfile(args.security_profile)
    node = None
    if args.config:
        from ..deployment import NodeConfig, build_node

        config = NodeConfig.from_file(args.config)
        config.state_dir = args.state_dir if args.state_dir != Path(".fasp") else config.state_dir
        config.base_url = base_url
        config.profile = profile
        try:
            node = build_node(config, adapter=load_adapter(args.adapter))
        except FaspError as error:
            raise SystemExit(f"{error.code}: {error.detail}") from error
        harness = node.harness
        health = node.health
        node.start_loops()
    else:
        harness = FaspHarness(
            args.state_dir,
            args.name,
            base_url,
            load_adapter(args.adapter),
            rate_limit_per_second=args.rate_limit_per_peer,
            rate_limit_burst=args.rate_limit_burst,
        )
        posture = evaluate_posture(
            DeploymentConfig(
                profile=profile,
                host=args.host,
                tls_cert=args.tls_cert,
                tls_key=args.tls_key,
                tls_client_ca=args.tls_client_ca,
                insecure_http=args.insecure_http,
                state_dir=args.state_dir,
                rate_limit_per_peer=args.rate_limit_per_peer,
                ip_rate_limit_per_second=args.ip_rate_limit_per_second,
                audit_verified=harness.audit.verify()[0],
            )
        )
        if not posture.acceptable:
            print(posture.render_text())
            raise SystemExit(f"Refusing to start in the {profile.value} security profile.")
        health = default_health(harness)

    app = build_asgi_app(harness, args.ip_rate_limit_per_second, args.ip_rate_limit_burst, health)

    print(f"FASP harness for {harness.identity.system_id}")
    print(f"Profile: {base_url}/profile  ({profile.value} security profile)")
    print(f"Admin token file: {args.state_dir / 'admin_token'} (keep private)")
    if node is not None:
        print(f"Safety controller: {node.supervisor.driver.describe()['model'] if node.supervisor and node.supervisor.driver else 'none observed'}")
        print(f"Fleets: {', '.join(node.registry.fleets) or 'none'}   Leader: {node.lease.is_leader if node.lease else 'single-node'}")

    config_kwargs: dict[str, object] = {}
    if secure:
        config_kwargs["ssl_certfile"] = str(args.tls_cert)
        config_kwargs["ssl_keyfile"] = str(args.tls_key)
        config_kwargs["ssl_context_factory"] = _tls13_only_context_factory
        if args.tls_client_ca:
            config_kwargs["ssl_ca_certs"] = str(args.tls_client_ca)
            config_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED

    server_config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info", **config_kwargs)
    try:
        uvicorn.Server(server_config).run()
    finally:
        if node is not None:
            node.stop()


if __name__ == "__main__":
    main()
