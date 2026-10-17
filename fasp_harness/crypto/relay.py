"""End-to-end encryption for opaque relay frames.

The recipient's X25519 key is advertised in its Ed25519-signed ID card.
An ephemeral sender key, HKDF-SHA256 and ChaCha20-Poly1305 protect each
frame. The outer record is also Ed25519-signed to authenticate its sender.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..protocol.errors import FaspError
from ..timestamps import now, parse_stamp
from .envelope import b64, sign, unb64, verify
from .identity import Identity, atomic_json

RELAY_FRAME_LIMIT = 96 * 1024


class RelayKey:
    def __init__(self, private: X25519PrivateKey) -> None:
        self.private = private
        self.public_b64 = b64(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    @classmethod
    def load_or_create(cls, path: Path) -> RelayKey:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(X25519PrivateKey.from_private_bytes(unb64(data["private_key"])))
        private = X25519PrivateKey.generate()
        atomic_json(path, {"private_key": b64(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))})
        return cls(private)

    def seal(self, identity: Identity, to: str, recipient_public: str, message_id: str, kind: str, body: dict[str, Any], expires_at: str) -> dict[str, Any]:
        try:
            recipient = X25519PublicKey.from_public_bytes(unb64(recipient_public))
        except (ValueError, TypeError) as exc:
            raise FaspError("auth.invalid_relay_key", "Peer has no valid signed relay encryption key; refresh its pairing card.") from exc
        if len(unb64(recipient_public)) != 32:
            raise FaspError("auth.invalid_relay_key", "Peer relay encryption key has invalid length.")
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = b64(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        aad = f"fasp-relay-v1|{identity.system_id}|{to}|{message_id}|{kind}|{expires_at}".encode()
        key = HKDF(algorithm=SHA256(), length=32, salt=None, info=aad).derive(ephemeral.exchange(recipient))
        nonce = os.urandom(12)
        plaintext = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(plaintext) > 64 * 1024:
            raise FaspError("resource.too_large", "Relay plaintext exceeds 64 KiB.")
        frame = sign({"version": 1, "from": identity.system_id, "to": to, "message_id": message_id, "kind": kind, "expires_at": expires_at, "ephemeral_key": ephemeral_public, "nonce": b64(nonce), "ciphertext": b64(ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad))}, identity.private, identity.kid)
        if len(json.dumps(frame, separators=(",", ":")).encode()) > RELAY_FRAME_LIMIT:
            raise FaspError("resource.too_large", "Encrypted relay frame exceeds 96 KiB.")
        return frame

    def open(self, frame: dict[str, Any], sender_card: dict[str, Any], own_id: str) -> dict[str, Any]:
        if not isinstance(frame, dict) or len(json.dumps(frame, separators=(",", ":")).encode()) > RELAY_FRAME_LIMIT:
            raise FaspError("resource.too_large", "Relay frame exceeds 96 KiB.")
        if frame.get("version") != 1 or frame.get("to") != own_id or frame.get("from") != sender_card.get("system_id") or frame.get("kind") not in {"request", "response"}:
            raise FaspError("auth.invalid_relay_frame", "Relay frame identity or version is invalid.")
        verify(frame, sender_card["public_key"])
        try:
            if parse_stamp(frame["expires_at"]) <= now():
                raise ValueError("expired")
        except (KeyError, TypeError, ValueError) as exc:
            raise FaspError("auth.invalid_relay_frame", "Relay frame has expired or has an invalid expiry.") from exc
        try:
            remote = X25519PublicKey.from_public_bytes(unb64(frame["ephemeral_key"]))
            nonce = unb64(frame["nonce"])
            if len(nonce) != 12:
                raise ValueError("bad nonce")
            aad = f"fasp-relay-v1|{frame['from']}|{own_id}|{frame['message_id']}|{frame['kind']}|{frame['expires_at']}".encode()
            key = HKDF(algorithm=SHA256(), length=32, salt=None, info=aad).derive(self.private.exchange(remote))
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, unb64(frame["ciphertext"]), aad)
            if len(plaintext) > 64 * 1024:
                raise ValueError("oversized plaintext")
            body = json.loads(plaintext)
            if not isinstance(body, dict):
                raise ValueError("non-object plaintext")
            return body
        except (InvalidTag, ValueError, TypeError, KeyError, json.JSONDecodeError, RecursionError) as exc:
            # RecursionError: a hand-crafted plaintext can nest deeper than
            # the C scanner's budget while still fitting the 64 KiB cap. It
            # must become this same authenticated-decryption rejection, not
            # an exception that escapes `process_once` and ends the relay
            # worker thread for good.
            raise FaspError("auth.invalid_relay_frame", "Relay frame failed authenticated decryption.") from exc
