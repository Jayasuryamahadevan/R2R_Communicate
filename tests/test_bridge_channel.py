"""Actual TypeScript SDK handshake/reconnection, with deterministic socket faults."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fasp_harness.core import FaspHarness
from fasp_harness.crypto.envelope import verify


@unittest.skipUnless(shutil.which("node"), "Node 22+ is installed in CI")
class BridgeChannelTests(unittest.TestCase):
    def test_target_pinning_registration_queue_bounds_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            peer = FaspHarness(Path(directory) / "peer", "peer", "http://peer")
            other = FaspHarness(Path(directory) / "other", "other", "http://other")
            try:
                result = subprocess.run(
                    [shutil.which("node"), "--disable-warning=ExperimentalWarning", "tests/interop/node_channel.mjs"],
                    input=json.dumps({"card": peer.id_card(), "other_card": other.id_card()}),
                    capture_output=True,
                    text=True,
                    timeout=12,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertGreaterEqual(report["statuses"].count("open"), 2)
                for frame in report["frames"]:
                    self.assertEqual(frame["to"], peer.identity.system_id)
                    verify(frame, report["public_key"])
            finally:
                peer.close()
                other.close()

    def test_real_node_sdk_pairs_and_exchanges_frames_with_asgi_server(self):
        import socket
        import threading
        import time

        import uvicorn

        from fasp_harness.transport.http_app import create_app

        with tempfile.TemporaryDirectory() as directory:
            peer = FaspHarness(Path(directory), "real-node", "http://127.0.0.1")
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            url = f"http://127.0.0.1:{listener.getsockname()[1]}"
            server = uvicorn.Server(uvicorn.Config(create_app(peer), log_level="error"))
            thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.started:
                    self.assertTrue(thread.is_alive())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                result = subprocess.run(
                    [shutil.which("node"), "--disable-warning=ExperimentalWarning", "tests/interop/node_channel.mjs"],
                    input=json.dumps({"url": url, "admin_token": peer.admin_token}),
                    capture_output=True,
                    text=True,
                    timeout=12,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {"registered": True, "correlated": True})
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                listener.close()
                peer.close()
                self.assertFalse(thread.is_alive())
