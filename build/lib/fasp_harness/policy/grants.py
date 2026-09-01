"""Grant validation: "the stricter of local policy and the supplied grant wins" (ss8).

A grant is an ADDITIONAL, narrowing gate layered on top of a peer's
pairing-time `allowed_capability_prefixes` -- referencing one can never
grant more than pairing already scoped, only require a further, independently
valid, expiring authorization on top of it.
"""

from __future__ import annotations

from ..protocol.errors import FaspError
from ..storage.grants_repo import GrantsRepo
from ..timestamps import now, parse_stamp


def validate_grant_if_required(
    grants: GrantsRepo,
    peer_id: str,
    capability: str,
    grant_id: str | None,
    require_grant: bool,
) -> None:
    """Raise FaspError unless a referenced grant (when required) is valid.

    This is layered ON TOP OF the peer's base pairing-time capability-prefix
    check, which callers must run first (unchanged from the pre-grants
    design) -- a grant only ever narrows, so it must never be checked in
    place of that base gate.
    """
    if grant_id is None:
        if require_grant:
            raise FaspError("auth.not_authorized", "This capability's risk class requires an explicit grant.")
        return
    grant = grants.get(grant_id)
    if grant is None or grant["subject_peer"] != peer_id:
        raise FaspError("auth.not_authorized", "Referenced grant does not exist or was not issued to this peer.")
    if grant["revoked_at"] is not None:
        raise FaspError("auth.grant_expired", "Referenced grant has been revoked.")
    if parse_stamp(grant["expires_at"]) <= now():
        raise FaspError("auth.grant_expired", "Referenced grant has expired.")
    if not any(capability.startswith(prefix) for prefix in grant["capability_prefixes"]):
        raise FaspError("auth.not_authorized", "Referenced grant does not cover this capability.")
