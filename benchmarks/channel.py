"""Persistent TLS 1.3/mTLS WebSocket heartbeat RTT on loopback.

Both peers share this process/host. Excludes pairing, handshake and signing
from timed RTT; includes framed send, server validation/storage and response.
Run: python -m benchmarks.channel --iterations 1000
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import ipaddress
import json
import math
import platform
import socket
import ssl
import statistics
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from websockets.asyncio.client import connect

from fasp_harness.core import FaspHarness
from fasp_harness.crypto.canonical import canonicalize
from fasp_harness.transport.asgi_server import _tls13_only_context_factory
from fasp_harness.transport.http_app import create_app

SUPPORTS_VOLATILE = "delivery" in inspect.signature(FaspHarness.make_envelope).parameters


def certificates(directory: Path) -> tuple[Path, Path, Path]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    current = datetime.now(UTC)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FASP temporary benchmark CA")])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(current - timedelta(minutes=1)).not_valid_after(current + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=None, decipher_only=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(minutes=1)).not_valid_after(current + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                        data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                        encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = directory / "ca.pem", directory / "cert.pem", directory / "key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.touch(mode=0o600)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_path, cert_path, key_path


async def exercise(alice: FaspHarness, bob: FaspHarness, url: str, context: ssl.SSLContext, iterations: int) -> dict:
    results = {}
    async with connect(url, ssl=context, compression=None, max_size=65536) as channel:
        for delivery in (("durable", "volatile") if SUPPORTS_VOLATILE else ("durable",)):
            samples = []
            changes = bob.db.connection.total_changes
            for index in range(iterations + 20):
                envelope = (alice.make_envelope("heartbeat", bob.identity.system_id, {}, delivery=delivery, receiver_instance=bob.instance_id)
                            if SUPPORTS_VOLATILE else alice.make_envelope("heartbeat", bob.identity.system_id, {}))
                wire = canonicalize(envelope).decode()
                started = time.perf_counter_ns()
                await channel.send(wire)
                response = json.loads(await channel.recv())
                elapsed = (time.perf_counter_ns() - started) / 1_000_000
                if response.get("type") != "heartbeat":
                    raise RuntimeError(f"Benchmark request rejected: {response}")
                if index >= 20:
                    samples.append(elapsed)
            samples.sort()
            results[delivery] = {"samples": len(samples), "unit": "ms", "mean": statistics.mean(samples),
                                 **{key: samples[math.ceil(len(samples) * fraction) - 1] for key, fraction in (("p50", .5), ("p95", .95), ("p99", .99))},
                                 "sqlite_row_changes_including_warmup": bob.db.connection.total_changes - changes}
    if SUPPORTS_VOLATILE and results["volatile"]["sqlite_row_changes_including_warmup"]:
        raise AssertionError("Valid volatile observations wrote to SQLite")
    return results


def run(iterations: int) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ca, cert, key = certificates(root)
        alice = FaspHarness(root / "alice", "alice", "https://localhost")
        volatile_options = {"volatile_rate_limit_per_second": 100000, "volatile_rate_limit_burst": iterations + 100} if SUPPORTS_VOLATILE else {}
        bob = FaspHarness(root / "bob", "bob", "https://localhost", rate_limit_burst=iterations + 100, **volatile_options)
        hello = bob.hello(alice.id_card())
        bob.confirm_peer(alice.identity.system_id, hello["pair_code"])
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        config = uvicorn.Config(create_app(bob), host="127.0.0.1", port=port, log_level="error", ws_max_size=65536,
                                ssl_certfile=str(cert), ssl_keyfile=str(key), ssl_ca_certs=str(ca), ssl_cert_reqs=ssl.CERT_REQUIRED,
                                ssl_context_factory=_tls13_only_context_factory)
        server = uvicorn.Server(config)
        thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                if not thread.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError("Benchmark TLS server failed to start")
                time.sleep(.01)
            context = ssl.create_default_context(cafile=str(ca))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(str(cert), str(key))
            timings = asyncio.run(exercise(alice, bob, f"wss://127.0.0.1:{port}/fasp/v1/channel", context, iterations))
            return {"scope": __doc__, "platform": platform.platform(), "python": platform.python_version(),
                    "transport": "persistent loopback WebSocket, TLS 1.3, mutual certificates, compression disabled", "timings": timings}
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()
            alice.close()
            if thread.is_alive():
                raise RuntimeError("Benchmark TLS server did not shut down")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    if not 10 <= args.iterations <= 3000:
        parser.error("iterations must be 10..3000")
    print(json.dumps(run(args.iterations), indent=2))
