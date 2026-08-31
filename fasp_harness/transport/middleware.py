"""ASGI middleware: coarse IP-keyed rate limiting ahead of body parsing/auth.

Deliberately cruder than the peer-keyed limiter inside
`FaspHarness._verify_envelope` (`policy/ratelimit.py`): this one's only job
is to blunt a connection/request flood from a single address before a body
has even been read or a signature verified, which the peer-keyed limiter
can't do -- it only runs once we know who is asking (FASP_PROTOCOL.md ss10).
"""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ..core import PROTOCOL
from ..policy.ratelimit import TokenBucketLimiter


class IPRateLimitMiddleware:
    def __init__(self, app: ASGIApp, rate_per_second: float = 20.0, burst: int = 40) -> None:
        self.app = app
        self.limiter = TokenBucketLimiter(rate_per_second, burst)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        key = client[0] if client else "unknown"
        if not self.limiter.allow(key):
            response = JSONResponse(
                {"fasp": PROTOCOL, "type": "protocol.error", "error": {"code": "resource.exhausted", "detail": "Too many requests from this address."}},
                status_code=429,
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
