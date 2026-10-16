"""Small bounded HTTPS client for relay mailboxes."""

from __future__ import annotations

import json
import ssl
from typing import Any
from urllib import error, parse, request

from ..protocol.errors import FaspError


def check_relay_url(url: str) -> str:
    parts = parse.urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.path not in {"", "/"} or parts.query or parts.fragment or parts.username or parts.password:
        raise FaspError("schema.invalid", "Relay URL must be a bare HTTPS origin.")
    if parts.scheme != "https" and parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise FaspError("transport.tls_required", "Remote relay requires HTTPS.")
    return url.rstrip("/")


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def relay_http(origin: str, account: str, token: str, method: str, path: str, payload: dict[str, Any] | None = None, *, ca_cert: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    origin = check_relay_url(origin)
    if method not in {"GET", "POST"} or not path.startswith("/relay/v1/"):
        raise FaspError("schema.invalid", "Invalid relay request.")
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() if payload is not None else None
    if data is not None and len(data) > 98 * 1024:
        raise FaspError("resource.too_large", "Relay request exceeds size limit.")
    req = request.Request(origin + path, data=data, method=method, headers={"Authorization": f"Bearer {token}", "X-FASP-Relay-Account": account, "Content-Type": "application/json", "Accept": "application/json"})
    opener = request.build_opener(request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_cert)), _NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as response:
            body = response.read(2 * 1024 * 1024 + 1)
    except error.HTTPError as exc:
        try:
            problem = json.loads(exc.read(4096)).get("error", {})
        except (ValueError, TypeError):
            problem = {}
        code = str(problem.get("code", "transport.unreachable" if exc.code >= 500 else "transport.relay_rejected"))
        if exc.code >= 500:
            code = "transport.unreachable"
        elif exc.code == 429:
            code = "resource.exhausted"
        raise FaspError(code, str(problem.get("detail", "Relay rejected request."))) from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise FaspError("transport.unreachable", "Relay is unreachable.") from exc
    if len(body) > 2 * 1024 * 1024:
        raise FaspError("resource.too_large", "Relay response exceeds size limit.")
    try:
        result = json.loads(body)
        if not isinstance(result, dict):
            raise ValueError("non-object")
        return result
    except (UnicodeError, ValueError, TypeError) as exc:
        raise FaspError("transport.unreachable", "Relay returned invalid JSON.") from exc
