"""FASP protocol error type and the required error codes (FASP_PROTOCOL.md ss12)."""

from __future__ import annotations


class FaspError(Exception):
    """A protocol failure that is safe to return to a remote peer.

    Per ss12, the `detail` message MUST NOT contain secrets, stack traces,
    raw private logs, or identifiers -- callers that raise `FaspError` are
    responsible for keeping `detail` safe to transmit and log as-is.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# The required codes enumerated in ss12, kept here as documentation and for
# call sites that want a symbol instead of a string literal. FaspError does
# not restrict `code` to this set -- new families (e.g. `stream.*`,
# `fleet.*`, `safety.*`) extend it with their own namespaced codes.
AUTH_INVALID_SIGNATURE = "auth.invalid_signature"
AUTH_GRANT_EXPIRED = "auth.grant_expired"
AUTH_NOT_AUTHORIZED = "auth.not_authorized"
REPLAY_DETECTED = "replay.detected"
PROTOCOL_UNSUPPORTED_VERSION = "protocol.unsupported_version"
PROTOCOL_UNSUPPORTED_KIND = "protocol.unsupported_kind"
SCHEMA_INVALID = "schema.invalid"
RESOURCE_EXHAUSTED = "resource.exhausted"
CAPABILITY_UNAVAILABLE = "capability.unavailable"
POLICY_REQUIRES_CONFIRMATION = "policy.requires_confirmation"
LEASE_EXPIRED = "lease.expired"
SAFETY_PRECONDITION_FAILED = "safety.precondition_failed"
TASK_CANCELLED = "task.cancelled"
TASK_TOO_LATE = "task.too_late"
PRIVACY_DATA_MINIMIZATION = "privacy.data_minimization"
TRANSPORT_UNREACHABLE = "transport.unreachable"
