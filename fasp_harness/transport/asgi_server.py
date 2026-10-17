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
import math
import os
import ssl
import threading
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn

from ..core import FaspHarness
from ..protocol.errors import FaspError
from ..security.posture import DeploymentConfig, SecurityProfile, evaluate_posture
from ..timestamps import stamp
from .http_app import MAX_BODY_BYTES, create_app, default_health
from .middleware import IPRateLimitMiddleware
from .runtime import TransportLimits


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


def build_asgi_app(harness: FaspHarness, ip_rate_limit_per_second: float = 20.0, ip_rate_limit_burst: int = 40, health=None, before_close=None, *, transport_limits: TransportLimits | None = None):
    return IPRateLimitMiddleware(create_app(harness, health, before_close, transport_limits=transport_limits), ip_rate_limit_per_second, ip_rate_limit_burst)


def _tls13_only_context_factory(config: uvicorn.Config, default_factory):
    context: ssl.SSLContext = default_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def advertised_url(host: str, port: int, public_url: str | None, secure: bool) -> str:
    """Return a usable ID-card endpoint or fail before creating node state."""
    if host in {"0.0.0.0", "::"} and not public_url:
        raise SystemExit("A wildcard listener needs --public-url with the DNS name or IP address peers can reach.")
    if public_url:
        url = public_url.rstrip("/")
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
            valid_port = parts.port is None or 1 <= parts.port <= 65535
        except ValueError as exc:
            raise SystemExit("--public-url has an invalid host or port.") from exc
        if (
            parts.scheme not in {"http", "https"}
            or not hostname
            or hostname in {"0.0.0.0", "::"}
            or (host in {"0.0.0.0", "::"} and hostname in {"localhost", "127.0.0.1", "::1"})
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or not valid_port
        ):
            raise SystemExit("--public-url must be a reachable http(s) URL without credentials, query, or fragment.")
        if secure and parts.scheme != "https":
            raise SystemExit("A TLS listener requires an https:// --public-url.")
        return url
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{'https' if secure else 'http'}://{display_host}:{port}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a model-agnostic FASP harness endpoint.")
    parser.add_argument("serve", nargs="?", default="serve")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--name", default="fasp-system")
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("FASP_STATE_DIR", ".fasp")).expanduser(), help="Private local state directory (or FASP_STATE_DIR).")
    parser.add_argument("--public-url", help="Advertised HTTPS/HTTP base URL; required for a reachable LAN peer.")
    parser.add_argument("--adapter", help="Optional local model adapter: module:object or module:factory")
    parser.add_argument("--relay-worker", action="store_true", help="Poll the configured outbound relay in this process, using this node's adapter and policy.")
    parser.add_argument("--relay-ca-cert", help="CA bundle for outbound relay HTTPS.")
    parser.add_argument("--relay-poll-interval", type=float, default=0.5)
    parser.add_argument("--process-adapter", action="store_true", help="Run a stateless model adapter in supervised subprocesses instead of in-process threads.")
    parser.add_argument("--tls-cert", type=Path, help="PEM certificate for production HTTPS.")
    parser.add_argument("--tls-key", type=Path, help="PEM private key for production HTTPS.")
    parser.add_argument("--tls-client-ca", type=Path, help="PEM CA bundle to require and verify client certificates (mTLS). Transport hardening only -- never a substitute for envelope-level peer authorization.")
    parser.add_argument("--insecure-http", action="store_true", help="Allow plain HTTP for isolated development LANs only.")
    parser.add_argument("--rfcomm-channel", type=int, help="Also listen on an authenticated Bluetooth Classic RFCOMM channel (1..30).")
    parser.add_argument("--ble-psm", type=lambda value: int(value, 0), help="Also listen on an authenticated BLE L2CAP LE_PSM (0x0080..0x00ff; Python 3.14+).")
    parser.add_argument("--bluetooth-address", default="00:00:00:00:00:00", help="Local Bluetooth adapter address; default binds any adapter.")
    parser.add_argument("--ble-address-type", choices=("public", "random"), default="public")
    parser.add_argument("--rate-limit-per-peer", type=float, default=10.0, help="Sustained signed-envelope requests per second, per paired peer.")
    parser.add_argument("--rate-limit-burst", type=int, default=20, help="Burst allowance on top of --rate-limit-per-peer.")
    parser.add_argument("--volatile-rate-limit-per-peer", type=float, default=1000.0, help="Separate signed live-observation budget per second over a persistent channel.")
    parser.add_argument("--volatile-rate-limit-burst", type=int, default=256)
    parser.add_argument("--ip-rate-limit-per-second", type=float, default=20.0, help="Sustained requests per second, per source address, before authentication.")
    parser.add_argument("--ip-rate-limit-burst", type=int, default=40)
    parser.add_argument("--config", type=Path, help="Node configuration JSON (see examples/node.json): safety controller, fleets, site map, HA. Without it this serves a plain coordination node.")
    parser.add_argument("--max-inflight-tasks", type=int, default=256, help="Persistent maximum number of active intent tasks.")
    parser.add_argument("--adapter-concurrency", type=int, default=8, help="Maximum concurrent local adapter calls.")
    parser.add_argument("--security-profile", choices=["development", "hardened", "production"], default=None, help="Startup gate. `production` requires mutual TLS and private state; configured ROS 2 and safety hardware must pass their own checks.")
    parser.add_argument("--ingress-work-workers", type=int, default=8, help="Concurrent work handlers; excess requests receive retryable overload.")
    parser.add_argument("--ingress-control-workers", type=int, default=4, help="Reserved control/status handlers, independent of work and telemetry.")
    parser.add_argument("--ingress-observation-workers", type=int, default=4, help="Reserved heartbeat/packet handlers.")
    parser.add_argument("--ingress-per-peer", type=int, default=2, help="In-flight requests per claimed peer in each ingress lane.")
    parser.add_argument("--max-channels", type=int, default=128, help="Total WebSockets, including those awaiting authentication.")
    parser.add_argument("--channel-auth-timeout", type=float, default=5.0, help="Seconds to complete the first authenticated channel exchange.")
    parser.add_argument("--body-timeout", type=float, default=10.0, help="Seconds to receive a complete bounded HTTP request body.")
    parser.add_argument("--max-connections", type=int, default=256, help="Uvicorn connection/task concurrency limit, including HTTP and WebSockets.")
    args = parser.parse_args()
    if not 1 <= args.max_connections <= 4096:
        parser.error("--max-connections must be from 1 to 4096.")
    try:
        transport_limits = TransportLimits(work_workers=args.ingress_work_workers, control_workers=args.ingress_control_workers,
                                           observation_workers=args.ingress_observation_workers, per_peer_per_lane=args.ingress_per_peer,
                                           max_channels=args.max_channels, auth_timeout_s=args.channel_auth_timeout, body_timeout_s=args.body_timeout)
    except ValueError as error:
        parser.error(str(error))

    secure = bool(args.tls_cert or args.tls_key)
    if bool(args.tls_cert) != bool(args.tls_key):
        raise SystemExit("--tls-cert and --tls-key must be supplied together.")
    if args.tls_client_ca and not secure:
        raise SystemExit("--tls-client-ca requires --tls-cert/--tls-key.")
    if not secure and args.host not in {"127.0.0.1", "localhost", "::1"} and not args.insecure_http:
        raise SystemExit("Refusing plain HTTP on a non-loopback interface. Use TLS or explicitly pass --insecure-http for an isolated development LAN.")
    base_url = advertised_url(args.host, args.port, args.public_url, secure)

    # The security gate runs before anything binds a socket or connects to
    # a controller: a deployment that would be refused is refused before it
    # can do anything at all.
    profile = SecurityProfile(args.security_profile) if args.security_profile else SecurityProfile.DEVELOPMENT
    if not 1 <= args.adapter_concurrency <= 64 or args.max_inflight_tasks < 1:
        raise SystemExit("Adapter concurrency must be 1..64; max-inflight-tasks must be positive.")
    if args.process_adapter and not args.adapter:
        raise SystemExit("--process-adapter requires --adapter module:factory.")
    if not math.isfinite(args.relay_poll_interval) or args.relay_poll_interval <= 0 or args.relay_poll_interval > 60:
        raise SystemExit("--relay-poll-interval must be greater than zero and at most 60 seconds.")
    if args.process_adapter:
        from ..adapter_worker import ProcessAdapter

        adapter = ProcessAdapter(args.adapter)
    else:
        adapter = load_adapter(args.adapter)
    node = None
    if args.config:
        from ..deployment import NodeConfig, build_node

        config = NodeConfig.from_file(args.config)
        config.state_dir = args.state_dir if args.state_dir != Path(".fasp") else config.state_dir
        config.base_url = base_url
        config.profile = SecurityProfile(args.security_profile) if args.security_profile else config.profile
        profile = config.profile
        listener_posture = DeploymentConfig(
            profile=profile,
            host=args.host,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
            tls_client_ca=args.tls_client_ca,
            insecure_http=args.insecure_http,
            state_dir=config.state_dir,
            rate_limit_per_peer=args.rate_limit_per_peer,
            ip_rate_limit_per_second=args.ip_rate_limit_per_second,
            max_inflight_tasks=args.max_inflight_tasks,
        )
        try:
            node = build_node(
                config,
                adapter=adapter,
                security_posture=listener_posture,
                rate_limit_per_second=args.rate_limit_per_peer,
                rate_limit_burst=args.rate_limit_burst,
                max_inflight_tasks=args.max_inflight_tasks,
                adapter_concurrency=args.adapter_concurrency,
                volatile_rate_limit_per_second=args.volatile_rate_limit_per_peer,
                volatile_rate_limit_burst=args.volatile_rate_limit_burst,
            )
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
            adapter,
            rate_limit_per_second=args.rate_limit_per_peer,
            rate_limit_burst=args.rate_limit_burst,
            max_inflight_tasks=args.max_inflight_tasks,
            adapter_concurrency=args.adapter_concurrency,
            volatile_rate_limit_per_second=args.volatile_rate_limit_per_peer,
            volatile_rate_limit_burst=args.volatile_rate_limit_burst,
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
                max_inflight_tasks=args.max_inflight_tasks,
                audit_verified=harness.audit.verify()[0],
            )
        )
        if not posture.acceptable:
            print(posture.render_text())
            raise SystemExit(f"Refusing to start in the {profile.value} security profile.")
        health = default_health(harness)

    from .radio import RadioEndpoint, RadioListener

    radio_listeners: list[RadioListener] = []
    relay_stop = threading.Event()
    relay_thread: threading.Thread | None = None
    reconcile_stop = threading.Event()

    def reconcile_loop() -> None:
        while not reconcile_stop.is_set():
            harness.tasks.expire_stale_leases(stamp())
            harness.recover_interrupted_intents()
            if callable(getattr(harness.adapter, "reconcile", None)):
                harness.reconcile_unknown_tasks()
            reconcile_stop.wait(10.0)

    reconcile_thread = threading.Thread(target=reconcile_loop, name="fasp-task-reconciler", daemon=True)
    reconcile_thread.start()
    health.register("task-reconciler", lambda: (reconcile_thread.is_alive(), "Task lease sweep and optional external reconciliation running"))
    if args.relay_worker:
        from .relay_client import RelayClient

        relay_client = RelayClient(harness, ca_cert=args.relay_ca_cert)

        def poll_relay() -> None:
            while not relay_stop.is_set():
                try:
                    relay_client.process_once()
                except (FaspError, OSError) as error:
                    print(f"Relay poll failed: {error}")
                except Exception as error:  # noqa: BLE001 - this worker is never restarted
                    # A single poisonous frame must not end mailbox delivery
                    # for the lifetime of the process: the exception is
                    # reported and the next poll continues.
                    print(f"Relay poll failed unexpectedly: {error.__class__.__name__}: {error}")
                relay_stop.wait(args.relay_poll_interval)

        relay_thread = threading.Thread(target=poll_relay, name="fasp-relay-worker", daemon=True)
        relay_thread.start()
        health.register("relay-worker", lambda: (bool(relay_thread and relay_thread.is_alive()), "Outbound relay worker running"))
    try:
        if args.rfcomm_channel is not None:
            radio_listeners.append(RadioListener(harness, RadioEndpoint("classic", args.bluetooth_address, channel=args.rfcomm_channel)))
        if args.ble_psm is not None:
            radio_listeners.append(RadioListener(harness, RadioEndpoint("ble", args.bluetooth_address, psm=args.ble_psm, address_type=args.ble_address_type)))
        for listener in radio_listeners:
            listener.start()
            health.register(
                f"bluetooth-{listener.endpoint.mode}",
                lambda active=listener: (bool(active.thread and active.thread.is_alive()), "Bluetooth listener running"),
                critical=True,
            )
    except (FaspError, OSError) as error:
        for listener in radio_listeners:
            listener.close()
        if node is not None:
            node.stop()
        raise SystemExit(f"Bluetooth listener failed: {error}") from error

    def close_radios() -> None:
        reconcile_stop.set()
        reconcile_thread.join(timeout=5)
        relay_stop.set()
        if relay_thread is not None:
            relay_thread.join(timeout=5)
        for listener in radio_listeners:
            listener.close()

    app = build_asgi_app(harness, args.ip_rate_limit_per_second, args.ip_rate_limit_burst, health, close_radios, transport_limits=transport_limits)

    print(f"FASP harness for {harness.identity.system_id}")
    print(f"Profile: {base_url}/profile  ({profile.value} security profile)")
    print(f"Admin token file: {harness.state.directory / 'admin_token'} (keep private)")
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

    server_config = uvicorn.Config(
        app, host=args.host, port=args.port, log_level="info",
        ws_max_size=MAX_BODY_BYTES, ws_max_queue=16, limit_concurrency=args.max_connections, **config_kwargs,
    )
    try:
        uvicorn.Server(server_config).run()
    finally:
        close_radios()
        if node is not None:
            node.stop()


if __name__ == "__main__":
    main()
