"""Conformance test against the official RFC 8785 (JCS) test vectors.

See tests/vendor_vectors/README.md for provenance.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from fasp_harness.crypto.canonical import canonicalize

VECTORS_DIR = Path(__file__).parent / "vendor_vectors"
VECTOR_NAMES = ["arrays", "french", "structures", "unicode", "values", "weird"]


class CanonicalVectorTests(unittest.TestCase):
    def test_official_vectors_round_trip_to_canonical_bytes(self) -> None:
        for name in VECTOR_NAMES:
            with self.subTest(vector=name):
                input_text = (VECTORS_DIR / "input" / f"{name}.json").read_text(encoding="utf-8")
                expected = (VECTORS_DIR / "output" / f"{name}.json").read_bytes()
                parsed = json.loads(input_text)
                self.assertEqual(canonicalize(parsed), expected)


if __name__ == "__main__":
    unittest.main()
