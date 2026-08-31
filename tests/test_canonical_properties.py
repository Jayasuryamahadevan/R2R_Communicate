"""Property-based tests for RFC 8785 canonicalization.

Fixed-example conformance against the official vectors lives in
tests/test_canonical_vectors.py; these tests instead probe invariants that
hand-picked examples reliably miss, per FASP_PROTOCOL.md ss5's requirement
that every signature depend on canonicalization being exactly right.
"""

from __future__ import annotations

import re
import unittest

from hypothesis import given, settings
from hypothesis import strategies as st

from fasp_harness.crypto.canonical import canonicalize

# RFC 8785 numbers are IEEE 754 doubles; JCS additionally restricts integers
# to the safe-integer domain (see fasp_harness/crypto/canonical.py).
_SAFE_INT_MAX = 2**53 - 1

_safe_int = st.integers(min_value=-_SAFE_INT_MAX, max_value=_SAFE_INT_MAX)
_safe_float = st.floats(allow_nan=False, allow_infinity=False, width=64)
_safe_text = st.text(alphabet=st.characters(exclude_categories=("Cs",)), max_size=12)

_json_scalar = st.one_of(st.none(), st.booleans(), _safe_int, _safe_float, _safe_text)

_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(_safe_text, children, max_size=5),
    ),
    max_leaves=20,
)


class CanonicalPropertyTests(unittest.TestCase):
    @given(_json_value)
    @settings(max_examples=200)
    def test_canonicalize_is_deterministic(self, value: object) -> None:
        self.assertEqual(canonicalize(value), canonicalize(value))

    @given(st.dictionaries(_safe_text, _json_scalar, min_size=1, max_size=8))
    @settings(max_examples=200)
    def test_dict_key_order_does_not_affect_canonical_bytes(self, value: dict) -> None:
        shuffled = dict(reversed(list(value.items())))
        self.assertEqual(canonicalize(value), canonicalize(shuffled))

    @given(_json_value)
    @settings(max_examples=200)
    def test_canonical_bytes_have_no_insignificant_whitespace(self, value: object) -> None:
        # Whitespace may legitimately appear inside a JSON string literal's
        # content (as a raw byte or a \uXXXX/\n-style escape); strip every
        # string literal token before checking that no whitespace remains.
        encoded = canonicalize(value).decode("utf-8")
        without_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', encoded)
        for banned in (" ", "\n", "\t", "\r"):
            self.assertNotIn(banned, without_strings)


if __name__ == "__main__":
    unittest.main()
