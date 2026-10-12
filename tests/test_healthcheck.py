"""The container readiness probe exercises real TLS and client authentication."""

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fasp_harness.healthcheck import check_ready


class HealthcheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FASP test CA")])
        now = datetime.now(UTC)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        self.ca = root / "ca.crt"
        self.ca.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        def issue(name: str, purpose: x509.ObjectIdentifier, *, server: bool) -> tuple[Path, Path]:
            key = ec.generate_private_key(ec.SECP256R1())
            builder = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(ca_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            )
            if server:
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            cert_path, key_path = root / f"{name}.crt", root / f"{name}.key"
            cert_path.write_bytes(builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            )
            return cert_path, key_path

        self.server_cert, self.server_key = issue("node.example.internal", ExtendedKeyUsageOID.SERVER_AUTH, server=True)
        self.client_cert, self.client_key = issue("client", ExtendedKeyUsageOID.CLIENT_AUTH, server=False)

    def _serve_once(self, status: int) -> tuple[int, threading.Thread]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.server_cert, self.server_key)
        context.load_verify_locations(cafile=str(self.ca))
        context.verify_mode = ssl.CERT_REQUIRED
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve() -> None:
            with listener:
                connection, _ = listener.accept()
                try:
                    with context.wrap_socket(connection, server_side=True) as secured:
                        secured.recv(4096)
                        secured.sendall(f"HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii"))
                except ssl.SSLError:
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return port, thread

    def test_mtls_readiness_and_unready_response(self) -> None:
        for status, expected in ((200, True), (503, False)):
            with self.subTest(status=status):
                port, thread = self._serve_once(status)
                self.assertEqual(
                    check_ready("https://node.example.internal:8766", self.ca, self.client_cert, self.client_key, connect_port=port),
                    expected,
                )
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_wrong_advertised_name_is_rejected(self) -> None:
        port, thread = self._serve_once(200)
        with self.assertRaises(ssl.SSLCertVerificationError):
            check_ready("https://other.example.internal:8766", self.ca, self.client_cert, self.client_key, connect_port=port)
        thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
