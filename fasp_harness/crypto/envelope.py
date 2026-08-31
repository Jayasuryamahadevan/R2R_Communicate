"""Base64url encoding and Ed25519 signing/verification over canonical bytes.

`sign()`/`verify()` operate on any dict-shaped FASP record (envelope, ID
card, ...): every field except `signature` is canonicalized per RFC 8785
(see `.canonical`) and Ed25519-signed or verified against that exact byte
string.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..protocol.errors import FaspError
from .canonical import canonicalize


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def unsigned(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def sign(value: dict[str, Any], key: Ed25519PrivateKey, kid: str) -> dict[str, Any]:
    signed = dict(value)
    signed["signature"] = {"alg": "Ed25519", "kid": kid, "value": b64(key.sign(canonicalize(unsigned(signed))))}
    return signed


def verify(value: dict[str, Any], public_b64: str) -> None:
    signature = value.get("signature", {})
    if signature.get("alg") != "Ed25519" or not isinstance(signature.get("value"), str):
        raise FaspError("auth.invalid_signature", "Envelope has no supported Ed25519 signature.")
    try:
        Ed25519PublicKey.from_public_bytes(unb64(public_b64)).verify(unb64(signature["value"]), canonicalize(unsigned(value)))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise FaspError("auth.invalid_signature", "Signature verification failed.") from exc
