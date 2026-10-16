"""An independent native C producer interoperates with Python and Node FASP peers.

C code uses OpenSSL and fixed canonical FASP 1.0 message templates: a constrained
reference implementation, not a general-purpose canonical JSON encoder.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspError, FaspHarness

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "interop" / "native_c" / "fasp_peer.c"
NODE = ROOT / "interop" / "fasp-peer.mjs"


@unittest.skipUnless(shutil.which("cc"), "Native C conformance requires a C compiler")
class NativeCPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build_dir = tempfile.TemporaryDirectory()
        cls.executable = Path(cls.build_dir.name) / "fasp-c-peer"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(SOURCE),
             "-o", str(cls.executable), "-lcrypto"],
            check=True, capture_output=True, text=True, timeout=30,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.build_dir.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.identity = self.directory / "fasp.key"
        self.native("init", str(self.identity))
        self.receiver = FaspHarness(self.directory / "receiver", "receiver", "http://127.0.0.1:8766")

    def tearDown(self) -> None:
        self.receiver.close()
        self.temp.cleanup()

    def native(self, *args: str) -> str:
        return subprocess.run(
            [str(self.executable), *args], capture_output=True, text=True,
            check=True, timeout=15,
        ).stdout.strip()

    def test_c_identity_and_signed_card_verifies_in_python(self) -> None:
        card = json.loads(self.native("card", str(self.identity)))
        self.receiver.verify_id_card(card)
        self.assertEqual(self.native("id", str(self.identity)), card["system_id"])
        self.assertEqual(self.identity.stat().st_mode & 0o077, 0)
        self.assertIsNone(card["endpoints"]["profile"])

    def test_c_heartbeat_is_verified_and_deduplicated_by_real_receiver(self) -> None:
        card = json.loads(self.native("card", str(self.identity)))
        hello = self.receiver.hello(card)
        self.receiver.confirm_peer(card["system_id"], hello["pair_code"], ["observe.", "coordinate."])
        envelope = json.loads(self.native("heartbeat", str(self.identity), self.receiver.identity.system_id))
        repeated, first = self.receiver.accept(envelope)
        self.assertFalse(repeated)
        repeated, second = self.receiver.accept(envelope)
        self.assertTrue(repeated)
        self.assertEqual(first, second)
        envelope["payload"]["tampered"] = True
        with self.assertRaises(FaspError):
            self.receiver.accept(envelope)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for three-language verification")
    def test_node_independently_verifies_c_card(self) -> None:
        card = json.loads(self.native("card", str(self.identity)))
        path = self.directory / "card.json"
        path.write_text(json.dumps(card), encoding="utf-8")
        result = subprocess.run(
            [shutil.which("node"), str(NODE), "verify-card", "--file", str(path)],
            capture_output=True, text=True, check=True, timeout=15,
        )
        self.assertEqual(json.loads(result.stdout)["system_id"], card["system_id"])

    def test_private_seed_is_not_replaced_and_bad_recipients_are_rejected(self) -> None:
        first = self.identity.read_bytes()
        create = subprocess.run([str(self.executable), "init", str(self.identity)], capture_output=True, text=True)
        self.assertNotEqual(create.returncode, 0)
        self.assertEqual(first, self.identity.read_bytes())
        send = subprocess.run([str(self.executable), "heartbeat", str(self.identity), "not-a-peer"], capture_output=True, text=True)
        self.assertNotEqual(send.returncode, 0)


if __name__ == "__main__":
    unittest.main()
