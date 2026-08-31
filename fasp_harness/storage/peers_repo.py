"""Peer pairing state, backed by SQLite (`peers` table)."""

from __future__ import annotations

import json
import secrets
from typing import Any

from .db import Database


class PeersRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self, peer_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT * FROM peers WHERE peer_id = ?", (peer_id,))
        return _row_to_peer(row) if row else None

    def upsert_pending_or_seen(
        self,
        peer_id: str,
        card: dict[str, Any],
        pair_code: str,
        seen_at: str,
        default_prefixes: list[str],
    ) -> dict[str, Any]:
        """Create a pending pairing record, or refresh an existing one's card/pair_code/seen_at.

        An existing peer's `state` and `allowed_capability_prefixes` are
        left untouched -- a re-`hello()` from an already-paired peer must
        not silently reset it to pending or widen its grants.
        """
        with self.db.write() as conn:
            existing = conn.execute("SELECT peer_id FROM peers WHERE peer_id = ?", (peer_id,)).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO peers "
                    "(peer_id, public_key, display_name, card_json, state, allowed_capability_prefixes_json, pair_code, seen_at, paired_at) "
                    "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, NULL)",
                    (peer_id, card["public_key"], card.get("display_name"), json.dumps(card), json.dumps(default_prefixes), pair_code, seen_at),
                )
            else:
                conn.execute(
                    "UPDATE peers SET public_key = ?, display_name = ?, card_json = ?, pair_code = ?, seen_at = ? WHERE peer_id = ?",
                    (card["public_key"], card.get("display_name"), json.dumps(card), pair_code, seen_at, peer_id),
                )
        peer = self.get(peer_id)
        assert peer is not None
        return peer

    def confirm(
        self,
        peer_id: str,
        pair_code: str,
        paired_at: str,
        expires_at: str,
        prefixes: list[str] | None,
    ) -> dict[str, Any] | None:
        """Mark `peer_id` paired if `pair_code` matches, timing-safely. None if not.

        `expires_at` bounds the pairing itself (ss3.3's pairing record MUST
        carry one) -- re-pairing is required once it passes, it is not
        authority forever. Re-pairing here also clears any prior
        revocation, since a fresh pairing ceremony IS the re-pairing flow
        ss12 requires after a suspected key compromise.
        """
        with self.db.write() as conn:
            row = conn.execute("SELECT pair_code FROM peers WHERE peer_id = ?", (peer_id,)).fetchone()
            if row is None or not secrets.compare_digest(row["pair_code"], pair_code):
                return None
            if prefixes is not None:
                conn.execute(
                    "UPDATE peers SET state = 'paired', paired_at = ?, expires_at = ?, allowed_capability_prefixes_json = ? WHERE peer_id = ?",
                    (paired_at, expires_at, json.dumps(prefixes), peer_id),
                )
            else:
                conn.execute(
                    "UPDATE peers SET state = 'paired', paired_at = ?, expires_at = ? WHERE peer_id = ?",
                    (paired_at, expires_at, peer_id),
                )
            conn.execute("DELETE FROM revocations WHERE peer_id = ?", (peer_id,))
        return self.get(peer_id)

    def all(self) -> dict[str, dict[str, Any]]:
        return {row["peer_id"]: _row_to_peer(row) for row in self.db.read("SELECT * FROM peers")}


def _row_to_peer(row: Any) -> dict[str, Any]:
    return {
        "card": json.loads(row["card_json"]),
        "state": row["state"],
        "pair_code": row["pair_code"],
        "seen_at": row["seen_at"],
        "paired_at": row["paired_at"],
        "expires_at": row["expires_at"],
        "trust_tier": row["trust_tier"],
        "allowed_capability_prefixes": json.loads(row["allowed_capability_prefixes_json"]),
    }
