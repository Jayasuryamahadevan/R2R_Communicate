"""C HTTP client against a live FASP ASGI server (no Python on native peer)."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fasp_harness.core import FaspHarness
from fasp_harness.transport.http_app import create_app

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "interop" / "native_c"


@unittest.skipUnless(shutil.which("cc") and shutil.which("pkg-config"), "C compiler and pkg-config required")
class NativeHTTPPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        check = subprocess.run(["pkg-config", "--exists", "libcurl", "json-c", "openssl"])
        if check.returncode != 0:
            raise unittest.SkipTest("libcurl, json-c, and OpenSSL development packages required")
        cls.build = tempfile.TemporaryDirectory()
        cls.http = Path(cls.build.name) / "fasp-c-http"
        cls.signer = Path(cls.build.name) / "fasp-c-peer"
        flags = subprocess.run(
            ["pkg-config", "--cflags", "--libs", "libcurl", "json-c", "openssl"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2",
             str(C / "fasp_http.c"), "-o", str(cls.http), *flags],
            check=True, capture_output=True, text=True, timeout=30,
        )
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2",
             str(C / "fasp_peer.c"), str(C / "fasp_wire.c"), "-o", str(cls.signer), "-lcrypto"],
            check=True, capture_output=True, text=True, timeout=30,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.build.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "native.key"
        subprocess.run([str(self.signer), "init", str(self.key)], check=True, capture_output=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.receiver = FaspHarness(self.root / "receiver", "receiver", self.base, rate_limit_burst=100)
        config = uvicorn.Config(create_app(self.receiver), host="127.0.0.1", port=port, log_level="error", lifespan="off")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(100):
            with socket.socket() as sock:
                sock.settimeout(0.1)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.03)
        else:
            self.fail("Native test server did not bind")
        self.addCleanup(self.shutdown)

    def shutdown(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self.receiver.close()

    def native(self, *arguments: str, data: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.http), *arguments], input=data, text=True,
                              capture_output=True, timeout=15)

    def signer_json(self, *arguments: str) -> dict:
        output = subprocess.run([str(self.signer), *arguments], check=True,
                                capture_output=True, text=True, timeout=10)
        return json.loads(output.stdout)

    def approve(self) -> None:
        card = self.signer_json("card", str(self.key))
        hello = self.receiver.hello(card)
        self.receiver.confirm_peer(card["system_id"], hello["pair_code"], ["observe."])

    def test_profile_and_capability_advertisement(self) -> None:
        accepted = self.native("profile", self.base, self.receiver.identity.system_id)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        response = json.loads(accepted.stdout)
        self.assertIsInstance(response, dict)
        self.assertIn("versions", response)

    def test_approved_native_heartbeat_reaches_real_receiver(self) -> None:
        self.approve()
        msg = self.signer_json("heartbeat", str(self.key), self.receiver.identity.system_id)
        serialized = json.dumps(msg) + "\n"
        result = self.native("send", self.base, self.receiver.identity.system_id, data=serialized)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsInstance(json.loads(result.stdout), dict)
        # Duplicate delivery must not execute the same signed envelope again.
        second = self.native("send", self.base, self.receiver.identity.system_id, data=serialized)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(result.stdout), json.loads(second.stdout))

    def test_unpaired_native_peer_receives_protocol_error(self) -> None:
        msg = self.signer_json("heartbeat", str(self.key), self.receiver.identity.system_id)
        result = self.native("send", self.base, self.receiver.identity.system_id, data=json.dumps(msg) + "\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FASP request failed", result.stderr)

    def test_wrong_peer_or_recipient_and_insecure_remote_url_are_rejected(self) -> None:
        another = "fasp:system:" + "A" * 43
        result = self.native("profile", self.base, another)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity mismatch", result.stderr.lower())
        result = self.native("profile", "http://example.com", self.receiver.identity.system_id)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback", result.stderr)
        msg = self.signer_json("heartbeat", str(self.key), self.receiver.identity.system_id)
        msg["to"] = another
        result = self.native("send", self.base, self.receiver.identity.system_id, data=json.dumps(msg) + "\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recipient", result.stderr)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI required for TLS certificate test")
    def test_https_certificate_and_tls_pin_are_both_enforced(self) -> None:
        cert = self.root / "cert.pem"
        key = self.root / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ed25519", "-keyout", str(key),
             "-out", str(cert), "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost"],
            check=True, capture_output=True, timeout=10,
        )
        certificate = x509.load_pem_x509_certificate(cert.read_bytes())
        key_der = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        pin = "sha256//" + base64.b64encode(hashlib.sha256(key_der).digest()).decode("ascii")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = uvicorn.Config(create_app(self.receiver), host="127.0.0.1", port=port,
                                log_level="error", lifespan="off",
                                ssl_keyfile=str(key), ssl_certfile=str(cert))
        tls_server = uvicorn.Server(config)
        tls_thread = threading.Thread(target=tls_server.run, daemon=True)
        tls_thread.start()
        try:
            for _ in range(100):
                with socket.socket() as sock:
                    sock.settimeout(0.1)
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(0.03)
            else:
                self.fail("TLS server did not bind")
            url = f"https://localhost:{port}"
            no_pin = self.native("profile", url, self.receiver.identity.system_id)
            self.assertNotEqual(no_pin.returncode, 0)
            self.assertIn("requires an independently verified", no_pin.stderr)
            good = self.native("profile", url, self.receiver.identity.system_id,
                               "--ca", str(cert), "--pin", pin)
            self.assertEqual(good.returncode, 0, good.stderr)
            wrong = self.native("profile", url, self.receiver.identity.system_id,
                                "--ca", str(cert), "--pin", "sha256//" + "A" * 43 + "=")
            self.assertNotEqual(wrong.returncode, 0)
        finally:
            tls_server.should_exit = True
            tls_thread.join(timeout=5)

    def test_malformed_and_excess_input_is_rejected(self) -> None:
        self.assertNotEqual(self.native("send", self.base, self.receiver.identity.system_id, data="invalid\n").returncode, 0)
        oversized = '{"to":"' + "x" * 70000 + '"}\n'
        self.assertNotEqual(self.native("send", self.base, self.receiver.identity.system_id, data=oversized).returncode, 0)


if __name__ == "__main__":
    unittest.main()
