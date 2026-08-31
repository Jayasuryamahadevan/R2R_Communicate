"""Long-term Ed25519 system identity.

Kept as a lone 0600 file outside the durable-state store (SQLite, from
Phase 2 onward) on purpose: a private key doesn't benefit from transactional
guarantees, and keeping it separate means the database file can be backed
up, copied, or inspected without ever containing the one secret that must
never leak.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .envelope import b64, unb64


def atomic_json(path: Path, value: Any) -> None:
    """Write `value` as canonical JSON bytes, atomically, owner-only (0600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonicalize(value) + b"\n")
    os.replace(temporary, path)
    os.chmod(path, 0o600)


@dataclass(frozen=True)
class Identity:
    private: Ed25519PrivateKey
    public_b64: str
    system_id: str
    kid: str

    @classmethod
    def load_or_create(cls, path: Path) -> Identity:
        if path.exists():
            record = json.loads(path.read_text(encoding="utf-8"))
            private = Ed25519PrivateKey.from_private_bytes(unb64(record["private_key"]))
            public = b64(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            return cls(private, public, record["system_id"], record["kid"])
        private = Ed25519PrivateKey.generate()
        public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public = b64(public_raw)
        system_id = "fasp:system:" + b64(hashlib.sha256(public_raw).digest())
        identity = cls(private, public, system_id, "ed25519-" + secrets.token_hex(4))
        atomic_json(
            path,
            {
                "private_key": b64(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
                "system_id": system_id,
                "kid": identity.kid,
            },
        )
        return identity
