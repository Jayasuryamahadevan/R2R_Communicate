"""RFC 8785 (JSON Canonicalization Scheme) canonical serialization.

Every FASP signature depends on this being byte-for-byte correct across
languages and implementations (FASP_PROTOCOL.md ss3.4, ss5). Rather than
hand-write the ECMA-262 number-formatting and UTF-16 key-ordering rules RFC
8785 requires -- exactly the kind of subtly-wrong-looking-right code this
project's own prior `core.canonical()` docstring admitted to being -- this
wraps a small, pinned, single-purpose third-party implementation:
`rfc8785` (Trail of Bits, Apache-2.0, zero transitive dependencies, itself
adapted from the JCS reference implementation at
https://github.com/cyberphone/json-canonicalization). Pinning an exact
version and verifying it against the official test vectors ourselves
(tests/test_canonical_vectors.py) gives both auditability and a path to
upstream security fixes, which copy-pasting a vendored fork would forfeit.
"""

from __future__ import annotations

from typing import Any

import rfc8785

CanonicalizationError = rfc8785.CanonicalizationError


def canonicalize(value: Any) -> bytes:
    """Serialize `value` to its RFC 8785 canonical JSON byte representation.

    Raises `CanonicalizationError` (a `ValueError` subclass) for values RFC
    8785 cannot represent: NaN/infinite floats, integers outside the IEEE
    754 double safe-integer domain, or non-string object keys.
    """
    return rfc8785.dumps(value)
