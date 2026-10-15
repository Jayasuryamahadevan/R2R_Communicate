"""Python ↔ Node JCS and Ed25519 conformance, using the real bridge encoder."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fasp_harness.crypto.canonical import canonicalize
from fasp_harness.crypto.envelope import b64, sign, unsigned, verify


@unittest.skipUnless(shutil.which("node"), "Node is required for independent wire conformance (installed in CI)")
class WireInteropTests(unittest.TestCase):
    def test_bridge_and_python_agree_on_unicode_numbers_identity_and_signatures(self) -> None:
        # Public, deterministic test key. Never use it as a node identity.
        seed = bytes(range(32))
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public = b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        system_id = "fasp:system:" + b64(hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).digest())
        base = {
            "fasp": "fasp/1.0", "kind": "stream.packet", "message_id": "interop-1", "from": system_id, "to": system_id,
            "issued_at": "2026-10-15T00:00:00Z", "expires_at": "2026-10-15T00:02:00Z", "nonce": "interop-test-nonce",
        }
        payloads = [
            {"speed_mps": 0.125, "uncertainty": 1e-7, "negative_zero": -0.0, "precise": 333333333.3333333},
            {"தமிழ்": "வணக்கம்", "\U0001f600": [True, False, None, 0], "\ufffd": "BMP", "\r": "control", "\u20ac": "€"},
            {"nested": [{"b": 2, "a": 1}], "max_integer": 2**53 - 1, "escaped": "\n\t\"\\"},
        ]
        records = [sign({**base, "payload": payload}, key, "interop-test") for payload in payloads]
        completed = subprocess.run(
            [shutil.which("node"), str(Path(__file__).parent / "interop/node_wire.mjs")],
            input=json.dumps({"test_seed_hex": seed.hex(), "records": records, "invalid": [1e20, "\ud800", 2**53]}),
            capture_output=True, text=True, check=True, timeout=10,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["public_key"], public)
        self.assertEqual(result["system_id"], system_id)
        self.assertTrue(all(result["rejects"]))
        for record, foreign in zip(records, result["records"], strict=True):
            self.assertEqual(foreign["canonical_b64"], b64(canonicalize(unsigned(record))))
            self.assertEqual(foreign["signature_b64"], record["signature"]["value"])
            self.assertTrue(foreign["python_signature_valid"])
            verify({**record, "signature": {**record["signature"], "value": foreign["signature_b64"]}}, public)
