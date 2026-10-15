"""Optional MCP round trips and concurrent clients over one durable node state."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from starlette.testclient import TestClient

from fasp_harness import agent_cli
from fasp_harness.core import FaspHarness
from fasp_harness.mcp_server import build_server
from fasp_harness.transport.http_app import create_app

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
        self.args = argparse.Namespace(state_dir=str(self.state), ca_cert=None, client_cert=None, client_key=None, insecure_http=False, timeout=5.0, limit=16, transport="auto")

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
                self.assertTrue({"identity", "communicate", "queue_intent", "drain"}.issubset({tool.name for tool in (await client.list_tools()).tools}))
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

    def test_communicate_reports_delivery_and_offline_queue(self) -> None:
        hello = self.alice.hello(self.bob.id_card())
        self.alice.confirm_peer(self.bob.identity.system_id, hello["pair_code"])
        reciprocal = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, reciprocal["pair_code"])
        self.alice.state.put("agent-peers.json", {self.bob.identity.system_id: "http://127.0.0.1:8862"})
        client = TestClient(create_app(self.bob))

        def local_request(url: str, payload: dict | None, args: argparse.Namespace) -> dict:
            del args
            path = urlsplit(url).path
            response = client.get(path) if payload is None else client.post(path, json=payload)
            return response.json()

        with patch.object(agent_cli, "request_json", side_effect=local_request):
            result = self._call("communicate", {"peer_id": self.bob.identity.system_id, "message": "MCP round trip", "idempotency_key": "mcp-1"})
        self.assertEqual(result["state"], "sent")
        self.assertEqual(result["response"]["response"]["output"]["summary"], "MCP round trip")
        self.assertEqual(self._call("outbox", {"message_id": result["message_id"]})["state"], "sent")

        with patch.object(agent_cli, "request_json", side_effect=agent_cli.TransportFailure("offline")):
            offline = self._call("communicate", {"peer_id": self.bob.identity.system_id, "message": "Later", "idempotency_key": "mcp-2"})
        self.assertEqual(offline["state"], "pending")
        self.assertIsNone(offline["response"])
        self.assertIn("offline", offline["last_error"])

    def test_cancelled_mcp_send_keeps_worker_database_open(self) -> None:
        pending = self.alice.hello(self.bob.id_card())
        self.alice.confirm_peer(self.bob.identity.system_id, pending["pair_code"])
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        failures: list[Exception] = []

        def slow_delivery(h: FaspHarness, args: argparse.Namespace) -> dict:
            del args
            entered.set()
            try:
                if not release.wait(timeout=5):
                    raise TimeoutError("delivery worker was not released")
                h.db.read_one("SELECT 1")
            except Exception as exc:
                failures.append(exc)
            finally:
                finished.set()
            return {}

        async def cancel_in_flight() -> None:
            server = build_server(self.args)
            operation = asyncio.create_task(server.call_tool("communicate", {"peer_id": self.bob.identity.system_id, "message": "cancelled caller"}))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                operation.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await operation
            finally:
                release.set()
            self.assertTrue(await asyncio.to_thread(finished.wait, 3))

        with patch("fasp_harness.mcp_server._deliver", side_effect=slow_delivery):
            asyncio.run(cancel_in_flight())
        self.assertEqual(failures, [])


    def test_device_management_tools_exist_and_are_fail_closed(self) -> None:
        async def list_names() -> set[str]:
            async with Client(build_server(self.args), raise_exceptions=True) as client:
                return {tool.name for tool in (await client.list_tools()).tools}

        self.assertTrue({"scan", "inspect", "connect", "approve", "disconnect", "capabilities", "ping"}.issubset(asyncio.run(list_names())))
        local = self._call("capabilities")
        self.assertEqual(local["peer_id"], self.alice.identity.system_id)
        denied = self._call("ping", {"peer_id": self.bob.identity.system_id})
        self.assertIn("auth.not_paired", denied["error"])
        denied = self._call("scan", {"cidr": "8.8.8.0/30"})
        self.assertIn("policy.discovery_scope", denied["error"])
        denied = self._call("disconnect", {"peer_id": self.bob.identity.system_id})
        self.assertIn("auth.pairing_not_found", denied["error"])

    def test_mcp_connect_and_local_approval(self) -> None:
        client = TestClient(create_app(self.bob))
        def local_request(url: str, payload: dict | None, args: argparse.Namespace) -> dict:
            del args
            path = urlsplit(url).path
            response = client.get(path) if payload is None else client.post(path, json=payload)
            return response.json()
        with patch.object(agent_cli, "request_json", side_effect=local_request):
            pending = self._call("connect", {"reference": "http://127.0.0.1:8862"})
        self.assertEqual(pending["state"], "pending")
        self.assertTrue(pending["approval_required"])
        approved = self._call("approve", {"peer_id": self.bob.identity.system_id, "pair_code": pending["pair_code"], "scopes": ["observe."]})
        self.assertEqual(approved["state"], "paired")
        revoked = self._call("disconnect", {"peer_id": self.bob.identity.system_id, "reason": "test revocation"})
        self.assertTrue(revoked["revoked"])


if __name__ == "__main__":
    unittest.main()
