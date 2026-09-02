"""Serve the twin over real HTTP, so the adapter is exercised over a socket.

An in-process fake proves the adapter's logic.  Only a socket proves the parts
that live below it: authentication round trips, cookie-scoped sessions, header
negotiation, connection loss, and TLS against a certificate the client has to
be told to trust.

TLS is offered because it reproduces the failure every OmniCore integration
meets first.  The controller presents a certificate the client does not know,
Python refuses it, and the documented fix is to trust the controller's CA
rather than to switch verification off.  `TwinServer` hands out that CA in PEM
form so the fix can be rehearsed rather than described.
"""

from __future__ import annotations

import datetime as dt
import http.cookies
import ipaddress
import ssl
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .controller import OmniCoreTwin
from .rws import RwsRequest, RwsService

SESSION_COOKIE = "ABBCX"


def self_signed_controller_cert(host: str = "127.0.0.1") -> tuple[bytes, bytes]:
    """A self-signed certificate and key, standing in for the controller's own."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FASP ABB twin")])
    now = dt.datetime.now(dt.UTC)
    names: list[x509.GeneralName] = [x509.DNSName("localhost")]
    try:
        names.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        names.append(x509.DNSName(host))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ABB-Twin"
    sys_version = ""

    def log_message(self, *args: Any) -> None:  # noqa: D102 - silence stderr access logging
        return

    # -- one request -------------------------------------------------------
    def _serve(self, method: str) -> None:
        service: RwsService = self.server.service  # type: ignore[attr-defined]
        split = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {name.lower(): value for name, value in self.headers.items()}
        session, issued = self._session(headers.get("cookie", ""))
        request = RwsRequest(
            method=method,
            path=split.path,
            query={key: values[-1] for key, values in urllib.parse.parse_qs(split.query).items()},
            headers=headers,
            body=body,
            session=session,
        )
        response = service.handle(request)
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        if issued:
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}={session}; Path=/; HttpOnly")
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if response.body:
            self.wfile.write(response.body)

    def _session(self, cookie_header: str) -> tuple[str, bool]:
        """Mastership is session-scoped on a real controller, so sessions are real here."""

        jar = http.cookies.SimpleCookie()
        jar.load(cookie_header) if cookie_header else None
        existing = jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else ""
        known: set[str] = self.server.sessions  # type: ignore[attr-defined]
        if existing and existing in known:
            return existing, False
        issued = f"s{len(known) + 1}"
        known.add(issued)
        return issued, True

    def do_GET(self) -> None:
        self._serve("GET")

    def do_POST(self) -> None:
        self._serve("POST")

    def do_PUT(self) -> None:
        self._serve("PUT")

    def do_DELETE(self) -> None:
        self._serve("DELETE")


class TwinServer:
    """A running RWS 2.0 endpoint in front of one `OmniCoreTwin`."""

    def __init__(
        self,
        controller: OmniCoreTwin,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        username: str = "fasp-pilot",
        password: str = "pilot-secret",
        tls: bool = False,
    ) -> None:
        self.controller = controller
        self.service = RwsService(controller, username=username, password=password)
        self.username = username
        self.password = password
        self.tls = tls
        self.ca_pem: bytes | None = None
        self._ca_file: Path | None = None
        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        self._httpd.service = self.service  # type: ignore[attr-defined]
        self._httpd.sessions = set()  # type: ignore[attr-defined]
        if tls:
            certificate, key = self_signed_controller_cert(host)
            self.ca_pem = certificate
            directory = Path(tempfile.mkdtemp(prefix="fasp-abb-twin-"))
            pair = directory / "controller.pem"
            pair.write_bytes(certificate + key)
            self._ca_file = directory / "controller-ca.pem"
            self._ca_file.write_bytes(certificate)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(pair)
            self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="fasp-abb-twin", daemon=True)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> TwinServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5.0)

    def __enter__(self) -> TwinServer:
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()

    # -- addressing --------------------------------------------------------
    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[0], self.port
        return f"{'https' if self.tls else 'http'}://{host}:{port}"

    def client_ssl_context(self) -> ssl.SSLContext | None:
        """The context a client needs to trust this controller, or None on HTTP.

        This is the rehearsal of the real commissioning step: the controller's
        certificate is trusted explicitly, verification stays on.
        """

        if not self.tls or self._ca_file is None:
            return None
        return ssl.create_default_context(cafile=str(self._ca_file))
