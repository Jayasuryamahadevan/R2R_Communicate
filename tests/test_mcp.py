"""Optional MCP round trips and concurrent clients over one durable node state."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.mcp_server import build_server

try:
    from mcp import Client, StdioServerParameters
except ImportError:
    Client = None


@unittest.skipUnless(Client is not None, "install the mcp extra")
class McpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.state = root / "alice"
        self.alice = FaspHarness(self.state, "Alice", "http://127.0.0.1:8861")
        self.bob = FaspHarness(root / "bob", "Bob", "http://127.0.0.1:8862")
        self.args = argparse.Namespace(state_dir=str(self.state))

    def tearDown(self) -> None:
        self.alice.close()
        self.bob.close()
        self.temp.cleanup()

    def _call(self, name: str, args: dict | None = None) -> dict:
        async def run() -> dict:
            async with Client(build_server(self.args), raise_exceptions=True) as client:
                result = await client.call_tool(name, args or {})
                if result.is_error:
                    return {"error": result.content[0].text}
                return json.loads(result.content[0].text)

        return asyncio.run(run())

    def test_identity_and_pairing_gate(self) -> None:
        self.assertEqual(self._call("identity")["system_id"], self.alice.identity.system_id)
        self.assertEqual(self._call("peers"), {"peers": []})
        denied = self._call("queue_intent", {"peer_id": self.bob.identity.system_id, "message": "hello"})
        self.assertIn("auth.not_paired", denied["error"])
        self.assertEqual(self._call("outbox")["depth"]["pending"], 0)

    def test_real_stdio_subprocess(self) -> None:
        async def run() -> dict:
            command = StdioServerParameters(command=sys.executable, args=["-m", "fasp_harness", "mcp", "--state-dir", str(self.state)])
            async with Client(command, raise_exceptions=True) as client:
                self.assertIn("identity", [tool.name for tool in (await client.list_tools()).tools])
                result = await client.call_tool("identity", {})
                return json.loads(result.content[0].text)

        self.assertEqual(asyncio.run(run())["system_id"], self.alice.identity.system_id)

    def test_concurrent_clients_queue_distinct_signed_messages(self) -> None:
        pending = self.alice.hello(self.bob.id_card())
        self.alice.confirm_peer(self.bob.identity.system_id, pending["pair_code"])
        def queue(index: int) -> dict:
            return self._call("queue_intent", {"peer_id": self.bob.identity.system_id, "message": f"message {index}"})
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(queue, range(12)))
        self.assertTrue(all(item["state"] == "queued" for item in results), results)
        self.assertEqual(len({item["message_id"] for item in results}), 12)
        self.assertEqual(self._call("outbox")["depth"]["pending"], 12)
        for result in results:
            self.assertEqual(self._call("outbox", {"message_id": result["message_id"]})["state"], "pending")


if __name__ == "__main__":
    unittest.main()
