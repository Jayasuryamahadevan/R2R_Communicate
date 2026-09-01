"""Structured JSON logging with secret redaction (FASP_PROTOCOL.md ss12: "MUST
NOT place secrets, stack traces, raw private logs, or identifiers in errors").

Call sites in this project only ever log a small, deliberately-chosen set
of fields (envelope kind, peer_id, protocol error code/detail, message_id)
-- never raw payloads, signatures, or key material. `RedactingFilter` is a
defense-in-depth backstop for that discipline, not the primary mechanism:
it scrubs a fixed set of known-sensitive field names should one ever slip
into a log call by accident.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from ..timestamps import stamp

REDACTED_KEYS = frozenset({
    "payload",
    "signature",
    "private_key",
    "admin_token",
    "pair_code",
    "envelope_json",
    "card_json",
})
REDACTED_PLACEHOLDER = "[REDACTED]"


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: (REDACTED_PLACEHOLDER if key in REDACTED_KEYS else _redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            record.fields = _redact(fields)
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # logging.Formatter.formatTime() is built on time.strftime(), which
        # (unlike datetime.strftime()) has no %f -- reuse this project's own
        # stamp() helper instead of a formatTime() call that would silently
        # emit a literal "%f" in every log line.
        entry: dict[str, Any] = {
            "ts": stamp(datetime.fromtimestamp(record.created, tz=UTC)),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry.update(fields)
        return json.dumps(entry, ensure_ascii=False, separators=(",", ":"))


def configure(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the `fasp_harness` logger: one JSON object per
    line to stderr, with `RedactingFilter` always attached."""
    logger = logging.getLogger("fasp_harness")
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
    return logger


def log(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    """`log(logger, logging.INFO, "envelope.accepted", kind=..., peer_id=...)`."""
    logger.log(level, event, extra={"fields": fields})
