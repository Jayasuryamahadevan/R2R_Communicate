"""Import footprint and bounded slow-consumer behavior."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import unittest

from fasp_harness.channels import ConnectionRegistry


class LightweightImportTests(unittest.TestCase):
    def test_package_import_does_not_load_server_crypto_or_fleet(self) -> None:
        result = subprocess.run([sys.executable, "-c", "import fasp_harness, json, sys; print(json.dumps(sorted(sys.modules)))"], capture_output=True, text=True, check=True, timeout=10)
        names = json.loads(result.stdout)
        for prefix in ("fasp_harness.core", "fasp_harness.fleet", "starlette", "uvicorn", "cryptography"):
            self.assertFalse(any(name == prefix or name.startswith(prefix + ".") for name in names), prefix)

    def test_cli_help_does_not_import_server_or_fleet_stack(self) -> None:
        source = """
import contextlib, io, json, sys
from fasp_harness.__main__ import main
sys.argv = ['fasp', '--help']
with contextlib.redirect_stdout(io.StringIO()):
    assert main() == 0
print(json.dumps(sorted(sys.modules)))
"""
        result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True, check=True, timeout=10)
        names = json.loads(result.stdout)
        for prefix in ("fasp_harness.core", "fasp_harness.fleet", "fasp_harness.twin", "starlette", "uvicorn", "mcp"):
            self.assertFalse(any(name == prefix or name.startswith(prefix + ".") for name in names), prefix)

    def test_existing_package_exports_still_resolve(self) -> None:
        from fasp_harness import FaspHarness, LayerGuard
        from fasp_harness.core import FaspHarness as CoreHarness

        self.assertIs(FaspHarness, CoreHarness)
        self.assertEqual(LayerGuard.__name__, "LayerGuard")


class _SlowConnection:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.messages = []

    async def send_text(self, data) -> None:
        self.entered.set()
        await self.release.wait()
        self.messages.append(json.loads(data))


class BoundedChannelTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_consumer_has_a_fixed_pending_bound(self) -> None:
        registry = ConnectionRegistry(max_pending=2)
        registry.bind_loop(asyncio.get_running_loop())
        connection = _SlowConnection()
        self.assertTrue(registry.register("peer", connection))
        self.assertTrue(registry.push("peer", {"sample": 1}))
        self.assertTrue(registry.push("peer", {"sample": 2}))
        for _ in range(100):
            self.assertFalse(registry.push("peer", {"sample": 3}))
        self.assertEqual(registry._pending[connection], 2)
        self.assertEqual(registry.dropped, 100)
        await asyncio.wait_for(connection.entered.wait(), timeout=1)
        connection.release.set()
        for _ in range(100):
            if registry._pending[connection] == 0:
                break
            await asyncio.sleep(0.001)
        self.assertEqual(registry._pending[connection], 0)
        self.assertEqual(connection.messages, [{"sample": 1}, {"sample": 2}])

    async def test_slow_consumer_timeout_unregisters_connection(self) -> None:
        registry = ConnectionRegistry(send_timeout_s=0.01)
        registry.bind_loop(asyncio.get_running_loop())
        connection = _SlowConnection()
        registry.register("peer", connection)
        registry.push("peer", {})
        await asyncio.wait_for(connection.entered.wait(), timeout=1)
        for _ in range(100):
            if not registry.is_connected("peer"):
                break
            await asyncio.sleep(0.005)
        self.assertFalse(registry.is_connected("peer"))
        self.assertNotIn(connection, registry._pending)

    async def test_connection_counts_are_bounded(self) -> None:
        registry = ConnectionRegistry(max_connections=2, max_per_peer=1)
        one, two, three = _SlowConnection(), _SlowConnection(), _SlowConnection()
        self.assertTrue(registry.register("alice", one))
        self.assertFalse(registry.register("alice", two))
        self.assertTrue(registry.register("bob", two))
        self.assertFalse(registry.register("carol", three))
        registry.unregister("alice", one)
        self.assertTrue(registry.register("carol", three))

    async def test_pending_bytes_remain_reserved_until_disconnected_sends_finish(self) -> None:
        registry = ConnectionRegistry(max_pending_bytes=20)
        registry.bind_loop(asyncio.get_running_loop())
        connection = _SlowConnection()
        registry.register("peer", connection)
        self.assertTrue(registry.push("peer", {"sample": 1}))
        self.assertFalse(registry.push("peer", {"sample": 2}))
        await asyncio.wait_for(connection.entered.wait(), timeout=1)
        registry.unregister("peer", connection)
        self.assertGreater(registry.pending_bytes, 0)
        self.assertFalse(registry.register("peer", connection))
        connection.release.set()
        for _ in range(100):
            if registry.pending_bytes == 0:
                break
            await asyncio.sleep(.001)
        self.assertEqual(registry.pending_bytes, 0)
        self.assertNotIn(connection, registry._pending)
