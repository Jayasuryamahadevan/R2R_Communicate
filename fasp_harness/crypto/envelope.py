"""Base64url encoding and Ed25519 signing/verification over canonical bytes.

`sign()`/`verify()` operate on any dict-shaped FASP record (envelope, ID
card, ...): every field except `signature` is canonicalized per RFC 8785
(see `.canonical`) and Ed25519-signed or verified against that exact byte
string.
"""

from __future__ import annotations

import base64
import binascii
import re
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..protocol.errors import FaspError
from .canonical import canonicalize


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise ValueError("Expected unpadded base64url.")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except binascii.Error as error:
        raise ValueError("Invalid base64url encoding.") from error
    if b64(decoded) != value:
        raise ValueError("Noncanonical base64url encoding.")
    return decoded


def unsigned(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def sign(value: dict[str, Any], key: Ed25519PrivateKey, kid: str) -> dict[str, Any]:
    signed = dict(value)
    signed["signature"] = {"alg": "Ed25519", "kid": kid, "value": b64(key.sign(canonicalize(unsigned(signed))))}
    return signed


def verify(value: dict[str, Any], public_b64: str, *, expected_kid: str | None = None) -> None:
    try:
        content = canonicalize(unsigned(value)) if isinstance(value, dict) else b""
    except (ValueError, TypeError, RecursionError) as exc:
        raise FaspError("auth.invalid_signature", "Signature content is invalid.") from exc
    _verify_canonical(value, public_b64, content, expected_kid=expected_kid)


@lru_cache(maxsize=256)
def _public_key(public_b64: str) -> Ed25519PublicKey:
    """Cache immutable decoded keys, never authorization or verification results."""
    return Ed25519PublicKey.from_public_bytes(unb64(public_b64))


def _verify_canonical(value: dict[str, Any], public_b64: str, content: bytes, *, expected_kid: str | None = None) -> None:
    """Internal primitive; content must come from this request's validated record."""
    if not isinstance(value, dict):
        raise FaspError("auth.invalid_signature", "Signed record must be an object.")
    signature = value.get("signature", {})
    if (
        not isinstance(signature, dict)
        or signature.get("alg") != "Ed25519"
        or not isinstance(signature.get("value"), str)
        or not isinstance(signature.get("kid"), str)
        or not 1 <= len(signature["kid"]) <= 128
        or (expected_kid is not None and signature["kid"] != expected_kid)
    ):
        raise FaspError("auth.invalid_signature", "Envelope has no supported Ed25519 signature.")
    try:
        _public_key(public_b64).verify(unb64(signature["value"]), content)
    except (InvalidSignature, ValueError, TypeError, RecursionError) as exc:
        raise FaspError("auth.invalid_signature", "Signature verification failed.") from exc
