# RFC 8785 official test vectors

Source: https://github.com/cyberphone/json-canonicalization (Anders Rundgren),
`testdata/input/*.json` and `testdata/output/*.json`, fetched from the
`master` branch. Licensed under the Apache License, Version 2.0.

These pair each input JSON document with its official RFC 8785 canonical
form. `tests/test_canonical_vectors.py` parses each input file with the
standard `json` module (preserving Python's native int/float distinction)
and asserts that `fasp_harness.crypto.canonical.canonicalize()` produces the
matching output bytes.
