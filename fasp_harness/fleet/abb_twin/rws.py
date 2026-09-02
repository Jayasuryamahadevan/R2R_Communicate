"""The Robot Web Services 2.0 surface, as RobotWare 7 presents it.

Every route, status code, header rule, and response document here was taken
from ABB's published RWS 2.0 OpenAPI specification rather than from what the
adapter happens to send -- which is the only way a twin can find a bug instead
of agreeing with one.  Three rules in particular exist to catch an RWS 1.0
client that would otherwise appear to work:

- an unversioned `Accept: application/xhtml+xml` is answered **406**, because
  RWS 2.0 negotiates on `;v=2.0`;
- an unversioned form content type is answered **415**;
- the RWS 1.0 spellings -- `/rw/rapid/symbol/data/<sym>?action=set` and
  `/rw/panel/ctrlstate` -- are answered **404**, exactly as RobotWare 7 does.

Writing a RAPID symbol is gated in the controller's own order: user grant,
then operating mode (with RMMP in manual), then mastership, then the value.
Getting that order wrong is how a simulator lets a client through that the
robot would refuse.
"""

from __future__ import annotations

import base64
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from .controller import GRANT_RAPID_CURRVALUE, TRIPWIRES, OmniCoreTwin
from .rapid import parse_value, render

_ACCEPTED = ("application/xhtml+xml;v=2.0", "application/hal+json;v=2.0", "application/xhtml+xml;v=2.1", "application/hal+json;v=2.1")
_FORM_TYPE = "application/x-www-form-urlencoded;v=2.0"


@dataclass(frozen=True)
class RwsRequest:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes = b""
    session: str = "s1"


@dataclass(frozen=True)
class RwsResponse:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


def _document(li_class: str, title: str, values: dict[str, Any], *, base: str = "https://twin/") -> bytes:
    """Render one RWS resource in the `<span class="…">` shape clients parse."""

    spans = "".join(f'<span class={quoteattr(name)}>{escape(str(value))}</span>' for name, value in values.items())
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<html xmlns="http://www.w3.org/1999/xhtml">'
        f"<head><base href={quoteattr(base)}/></head>"
        '<body><div class="state"><a href="" rel="self"></a><ul>'
        f"<li class={quoteattr(li_class)} title={quoteattr(title)}>{spans}</li>"
        "</ul></div></body></html>"
    ).encode()


def _xhtml(li_class: str, title: str, values: dict[str, Any]) -> RwsResponse:
    return RwsResponse(200, _document(li_class, title, values), {"Content-Type": "application/xhtml+xml;v=2.0"})


class RwsService:
    """Routes one HTTP request against one `OmniCoreTwin`."""

    def __init__(self, controller: OmniCoreTwin, *, username: str = "fasp-pilot", password: str = "pilot-secret") -> None:
        self.controller = controller
        self.username = username
        self.password = password
        self.log: list[tuple[str, str, int]] = []
        #: Set to a symbol name to fail its next write with 503, once.  A
        #: controller really does drop requests; the pilot's retry path has to
        #: be exercised against one that does, not only against one that never
        #: fails.
        self.fail_write_once: str | None = None
        #: Sessions that have completed Basic authentication once.  RWS keeps an
        #: authenticated session in its cookie, which is why a client is expected
        #: to hold a cookie jar; a twin that re-challenged every request would
        #: double the observed request count and misreport the polling cost.
        self._sessions: set[str] = set()

    # -- entry point -------------------------------------------------------
    def handle(self, request: RwsRequest) -> RwsResponse:
        response = self._dispatch(request)
        self.log.append((request.method, request.path, response.status))
        return response

    def _dispatch(self, request: RwsRequest) -> RwsResponse:
        if request.session not in self._sessions:
            if not self._authenticated(request):
                return RwsResponse(401, b"", {"WWW-Authenticate": 'Basic realm="ABB Robot Web Services"'})
            self._sessions.add(request.session)

        tripwire = TRIPWIRES.get((request.method, request.path))
        if tripwire is not None:
            # Answer as the controller would, and remember that it was asked.
            self.controller.record_tripwire(request.method, request.path, tripwire)
            return RwsResponse(204)

        if not self._acceptable(request.headers.get("accept", "")):
            return RwsResponse(406)
        if request.method == "POST" and not self._form_typed(request.headers.get("content-type", "")):
            return RwsResponse(415)

        route = self._route(request)
        return route if route is not None else RwsResponse(404)

    # -- negotiation -------------------------------------------------------
    def _authenticated(self, request: RwsRequest) -> bool:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8", "replace")
        except (ValueError, IndexError):
            return False
        name, _, secret = decoded.partition(":")
        return name == self.username and secret == self.password

    @staticmethod
    def _acceptable(accept: str) -> bool:
        if not accept or "*/*" in accept:
            return True
        wanted = {part.strip().lower().replace(" ", "") for part in accept.split(",")}
        return any(candidate in wanted for candidate in _ACCEPTED)

    @staticmethod
    def _form_typed(content_type: str) -> bool:
        return content_type.strip().lower().replace(" ", "") == _FORM_TYPE

    # -- routing -----------------------------------------------------------
    def _route(self, request: RwsRequest) -> RwsResponse | None:
        method, path = request.method, request.path
        controller = self.controller

        if method == "GET" and path == "/ctrl/identity":
            return _xhtml("ctrl-identity-info", "identity", {
                "ctrl-name": controller.name,
                "ctrl-id": f"{controller.name}-ID",
                "ctrl-type": controller.controller_type,
                "ctrl-mac": "00:30:64:00:00:01",
            })
        if method == "GET" and path == "/rw/panel/opmode":
            return _xhtml("pnl-opmode", "opmode", {"opmode": controller.operation_mode})
        if method == "GET" and path == "/rw/panel/ctrl-state":
            return _xhtml("pnl-ctrlstate", "ctrlstate", {"ctrlstate": controller.controller_state})
        if method == "GET" and path == "/rw/rapid/execution":
            return _xhtml("ios-signalstate", "execution", {
                "ctrlexecstate": controller.execution_state,
                "rapidexeccycle": "forever",
                "hdtrun": "false",
            })
        if method == "GET" and path == "/users/rmmp":
            return _xhtml("user-rmmp", "state", {
                "status": "modify" if controller.has_rmmp(request.session) else "none",
                "rmmpheldbyme": "true" if controller.has_rmmp(request.session) else "false",
            })

        robtarget = _match(path, "/rw/motionsystem/mechunits/", "/robtarget")
        if method == "GET" and robtarget is not None:
            values: dict[str, Any] = dict(controller.robtarget)
            values.update({"cf1": 0, "cf4": 0, "cf6": 0, "cfx": 0})
            return _xhtml("ms-robtargets", "robtarget", values)

        if path.startswith("/rw/mastership"):
            return self._mastership(request)

        symbol_url = _match(path, "/rw/rapid/symbol/", "/data")
        if symbol_url is not None:
            return self._symbol(request, symbol_url)
        return None

    # -- mastership --------------------------------------------------------
    def _mastership(self, request: RwsRequest) -> RwsResponse | None:
        controller, path = self.controller, request.path
        if request.method == "GET" and path == "/rw/mastership":
            return _xhtml("mastership", "mastership", {
                "edit": controller.mastership_holder("edit") or "nomaster",
                "motion": controller.mastership_holder("motion") or "nomaster",
            })
        parts = path.strip("/").split("/")
        if len(parts) == 3 and request.method == "GET":  # rw/mastership/<domain>
            domain = parts[2]
            if domain not in {"edit", "motion"}:
                return None
            holder = controller.mastership_holder(domain)
            return _xhtml("mastership", domain, {
                "mastership": "nomaster" if holder is None else "master",
                "mastershipheldbyme": "true" if holder == request.session else "false",
            })
        if len(parts) == 4 and request.method == "POST":  # rw/mastership/<domain>/<action>
            _, _, domain, action = parts
            if domain not in {"edit", "motion"} or action not in {"request", "release"}:
                return None
            if action == "request":
                if controller.operation_mode != "AUTO" and not controller.has_rmmp(request.session):
                    # In manual mode mastership is only available after RMMP.
                    return RwsResponse(403)
                return RwsResponse(204) if controller.request_mastership(domain, request.session) else RwsResponse(409)
            return RwsResponse(204) if controller.release_mastership(domain, request.session) else RwsResponse(403)
        return None

    # -- RAPID symbol data -------------------------------------------------
    def _symbol(self, request: RwsRequest, symbol_url: str) -> RwsResponse | None:
        controller = self.controller
        parts = symbol_url.split("/")
        if len(parts) != 4 or parts[0] != "RAPID":
            return RwsResponse(400)
        _, task, module, symbol = parts
        if task != controller.task or module.lower() != controller.module.name.lower():
            return RwsResponse(404)
        if symbol not in controller.symbols():
            return RwsResponse(404)

        if request.method == "GET":
            return RwsResponse(
                200,
                (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<html xmlns="http://www.w3.org/1999/xhtml">'
                    '<head><base href="https://twin/rw/rapid/"/></head>'
                    '<body><div class="state"><a href={self} rel="self"></a><ul>'
                    f'<li class="rap-data" title={quoteattr(symbol_url)}><span class="value">{escape(controller.read_symbol(symbol))}</span></li>'
                    '<li class="rap-data-decl-pos" title="decl-pos"><span class="begin-row">9</span>'
                    '<span class="begin-column">2</span><span class="end-row">9</span><span class="end-column">34</span></li>'
                    "</ul></div></body></html>"
                ).replace("{self}", quoteattr(f"symbol/{symbol_url}/data")).encode(),
                {"Content-Type": "application/xhtml+xml;v=2.0"},
            )
        if request.method != "POST":
            return None

        # The controller's own order of refusal.  Grant first: an account
        # without it is refused whatever else it holds.
        if GRANT_RAPID_CURRVALUE not in controller.grants:
            return RwsResponse(403)
        if controller.operation_mode != "AUTO" and not controller.has_rmmp(request.session):
            return RwsResponse(403)

        implicit = request.query.get("mastership", "explicit").lower() == "implicit"
        if implicit:
            if not controller.request_mastership("edit", request.session):
                return RwsResponse(403)
        elif not controller.holds_mastership("edit", request.session):
            return RwsResponse(403)

        if self.fail_write_once == symbol:
            self.fail_write_once = None
            if implicit:
                controller.release_mastership("edit", request.session)
            return RwsResponse(503)

        try:
            form = {key: values[-1] for key, values in urllib.parse.parse_qs(request.body.decode("utf-8", "replace")).items()}
            if "value" not in form:
                return RwsResponse(400)
            value = parse_value(form["value"], controller.declared_type(symbol))
            controller.write_symbol(symbol, render(value))
        except Exception:
            return RwsResponse(400)
        finally:
            if implicit:
                controller.release_mastership("edit", request.session)
        return RwsResponse(204)


def _match(path: str, prefix: str, suffix: str) -> str | None:
    """Return the middle of `prefix<middle>suffix`, or None."""

    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    middle = path[len(prefix): len(path) - len(suffix)]
    return middle or None
