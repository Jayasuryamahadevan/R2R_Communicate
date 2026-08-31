"""Durable, replay-proof inbox of accepted envelopes (`envelopes_inbox` table)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..timestamps import parse_stamp
from .db import Database


class InboxRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def insert_if_new(self, envelope: dict[str, Any], received_at: str) -> bool:
        """Insert `envelope`; return False if `message_id` was already seen.

        The UNIQUE constraint on `message_id` is the replay-detection
        mechanism -- see the schema comment in migrations/0001_initial.sql.
        """
        try:
            with self.db.write() as conn:
                conn.execute(
                    "INSERT INTO envelopes_inbox "
                    "(message_id, conversation_id, causation_id, from_peer, kind, issued_at, received_at, envelope_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        envelope["message_id"],
                        envelope.get("conversation_id"),
                        envelope.get("causation_id"),
                        envelope["from"],
                        envelope["kind"],
                        envelope["issued_at"],
                        received_at,
                        json.dumps(envelope),
                    ),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def set_response(self, message_id: str, response: dict[str, Any] | None) -> None:
        with self.db.write() as conn:
            conn.execute(
                "UPDATE envelopes_inbox SET response_json = ? WHERE message_id = ?",
                (json.dumps(response) if response is not None else None, message_id),
            )

    def get_response(self, message_id: str) -> dict[str, Any] | None:
        row = self.db.read_one("SELECT response_json FROM envelopes_inbox WHERE message_id = ?", (message_id,))
        if row is None or row["response_json"] is None:
            return None
        return json.loads(row["response_json"])

    def pull_since(self, from_peer: str, cursor: float) -> list[dict[str, Any]]:
        """Envelopes previously sent BY `from_peer`, issued after `cursor`.

        Scoped to `from_peer` deliberately. This reference harness has a
        single recipient identity (`FaspHarness.identity.system_id`), so
        every stored envelope is already addressed to it; without this
        filter, any one paired peer could pull every other paired peer's
        message contents through this endpoint, which the least-privilege,
        zero-trust intent of FASP_PROTOCOL.md ss3.1/ss9.2 rules out.
        """
        # `kind != 'inbox.pull'` excludes the mailbox query itself: since
        # every dispatchable kind is now recorded here for replay dedup
        # (core.py's `accept()`), an `inbox.pull` call would otherwise see
        # its own past calls reflected back as "messages", which is pure
        # self-referential noise no consumer of this mailbox mirror wants.
        rows = self.db.read(
            "SELECT envelope_json, issued_at FROM envelopes_inbox WHERE from_peer = ? AND kind != 'inbox.pull' ORDER BY row_id",
            (from_peer,),
        )
        return [json.loads(row["envelope_json"]) for row in rows if parse_stamp(row["issued_at"]).timestamp() > cursor]
