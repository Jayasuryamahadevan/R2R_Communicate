"""Cross-runtime verification using an actual Python FASP receiver and independent Node peer."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.protocol.errors import FaspError

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "interop" / "fasp-peer.mjs"


@unittest.skipUnless(shutil.which("node"), "Node.js 22+ is needed for cross-runtime tests")
class PortablePeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.receiver = FaspHarness(self.root / "receiver", "receiver", "http://127.0.0.1:8766")
        self.state = self.root / "identity.json"
        self.node("init", "--state", str(self.state))

    def tearDown(self) -> None:
        self.receiver.close()
        self.temp.cleanup()

    def node(self, *args: str) -> dict:
        result = subprocess.run(
            [shutil.which("node"), str(CLIENT), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return json.loads(result.stdout)

    def test_node_identity_card_verifies_in_python(self) -> None:
        card = self.node("card", "--state", str(self.state))
        self.receiver.verify_id_card(card)
        self.assertIsNone(card["endpoints"]["envelopes"])
        self.assertEqual(card["signature"]["kid"], card["key_id"])

    def test_signed_node_request_is_accepted_and_deduplicated_by_python(self) -> None:
        card = self.node("card", "--state", str(self.state))
        hello = self.receiver.hello(card)
        self.receiver.confirm_peer(card["system_id"], hello["pair_code"], ["observe.", "coordinate."])
        envelope = self.node(
            "envelope", "--state", str(self.state), "--to", self.receiver.identity.system_id,
            "--kind", "heartbeat", "--payload", "{}",
        )
        duplicate, response = self.receiver.accept(envelope)
        self.assertFalse(duplicate)
        self.assertIsNotNone(response)
        repeated, original = self.receiver.accept(envelope)
        self.assertTrue(repeated)
        self.assertEqual(response, original)
        envelope["payload"]["forged"] = True
        with self.assertRaises(FaspError):
            self.receiver.accept(envelope)

    def test_node_verifies_python_card_and_rejects_tampering(self) -> None:
        card = self.receiver.id_card()
        path = self.root / "peer-card.json"
        path.write_text(json.dumps(card), encoding="utf-8")
        self.assertEqual(self.node("verify-card", "--file", str(path))["system_id"], self.receiver.identity.system_id)
        card["display_name"] = "tampered"
        path.write_text(json.dumps(card), encoding="utf-8")
        result = subprocess.run(
            [shutil.which("node"), str(CLIENT), "verify-card", "--file", str(path)],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
