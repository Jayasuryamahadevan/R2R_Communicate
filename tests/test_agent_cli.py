"""End-to-end agent CLI verification over FASP's real ASGI handlers.

Network I/O is replaced by an in-memory transport; message signatures,
pairing policy, SQLite migrations, receipts and outbox state remain real.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from starlette.testclient import TestClient

from fasp_harness import agent_cli
from fasp_harness.core import FaspHarness
from fasp_harness.transport.http_app import create_app


class AgentCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.alice_path = str(self.root / "alice")
        self.bob_path = str(self.root / "bob")
        self.alice_url = "http://127.0.0.1:8861"
        self.bob_url = "http://127.0.0.1:8862"
        self.alice = None
        self.bob = None
        self.offline = False
        self._run("init", "--state-dir", self.alice_path, "--name", "Alice", "--base-url", self.alice_url)
        self._run("init", "--state-dir", self.bob_path, "--name", "Bob", "--base-url", self.bob_url)
        self.alice = FaspHarness(Path(self.alice_path), "Alice", self.alice_url)
        self.bob = FaspHarness(Path(self.bob_path), "Bob", self.bob_url)
        self.clients = {8861: TestClient(create_app(self.alice)), 8862: TestClient(create_app(self.bob))}

    def tearDown(self) -> None:
        if self.alice is not None:
            self.alice.close()
        if self.bob is not None:
            self.bob.close()
        self.temp.cleanup()

    def _network(self, url, payload, args):
        parsed = urlsplit(url)
        if self.offline and parsed.path == "/fasp/v1/envelopes":
            raise agent_cli.TransportFailure("simulated partition")
        client = self.clients[parsed.port]
        response = client.get(parsed.path) if payload is None else client.post(parsed.path, json=payload)
        result = response.json()
        if response.status_code >= 400:
            problem = result.get("error", {})
            raise agent_cli.RemoteRejection(problem.get("code", "http.error"), problem.get("detail", "Rejected."), response.status_code)
        return result

    def _run(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(agent_cli, "request_json", side_effect=self._network), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = agent_cli.main(list(args))
        raw = stdout.getvalue().strip() or stderr.getvalue().strip()
        return code, json.loads(raw.splitlines()[-1])

    def _paired(self):
        rc, a = self._run("register", self.bob_url, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, a)
        self.assertTrue(a["approval_required"])
        rc, b = self._run("register", self.alice_url, "--state-dir", self.bob_path)
        self.assertEqual(rc, 0, b)
        self.assertEqual(a["pair_code"], b["pair_code"])
        rc, denied = self._run("communicate", self.bob.identity.system_id, "--message", "preapproval", "--state-dir", self.alice_path)
        self.assertEqual(rc, 2, denied)
        self.assertEqual(denied["error"]["code"], "auth.not_paired")
        for path, peer_id in ((self.alice_path, self.bob.identity.system_id), (self.bob_path, self.alice.identity.system_id)):
            rc, outcome = self._run("approve", peer_id, "--code", a["pair_code"], "--state-dir", path)
            self.assertEqual(rc, 0, outcome)
            self.assertEqual(outcome["state"], "paired")

    def test_registration_requires_explicit_bilateral_approval(self):
        self._paired()
        rc, result = self._run("peers", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0)
        self.assertEqual(result["peers"][0]["state"], "paired")

    def test_communicate_persists_delivery_receipt_and_task_status(self):
        self._paired()
        rc, result = self._run("communicate", self.bob.identity.system_id, "--message", "Hello from agent A", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, result)
        self.assertEqual(result["state"], "sent")
        reply = result["response"]
        self.assertEqual(reply["type"], "receipt.delivered")
        self.assertEqual(reply["message_id"], result["message_id"])
        self.assertEqual(reply["response"]["output"]["summary"], "Hello from agent A")
        rc, stored = self._run("outbox", result["message_id"], "--state-dir", self.alice_path)
        self.assertEqual(rc, 0)
        self.assertEqual(stored["response"], reply)

    def test_offline_queue_drains_with_original_signed_message(self):
        self._paired()
        self.offline = True
        rc, pending = self._run("communicate", self.bob.identity.system_id, "--message", "Reconnected", "--state-dir", self.alice_path)
        self.assertEqual(rc, 3, pending)
        self.assertEqual(pending["state"], "pending")
        self.offline = False
        # Make the next scheduled retry immediately due; avoid wall-clock
        # sleeps while still testing the persisted signed message and receipt.
        with self.alice.db.write() as conn:
            conn.execute("UPDATE outbox SET next_attempt_ms = 0 WHERE state = 'pending'")
        rc, delivered = self._run("drain", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, delivered)
        self.assertEqual(delivered["delivered"][0]["message_id"], pending["message_id"])
        self.assertEqual(delivered["depth"]["sent"], 1)
        rc, stored = self._run("outbox", pending["message_id"], "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, stored)
        self.assertEqual(stored["state"], "sent")

    def test_queue_only_and_raw_heartbeat(self):
        self._paired()
        payload = self.root / "heartbeat.json"
        payload.write_text("{}", encoding="utf-8")
        rc, queued = self._run("send", self.bob.identity.system_id, "--kind", "heartbeat", "--payload-file", str(payload), "--queue-only", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, queued)
        self.assertEqual(queued["state"], "queued")
        rc, sent = self._run("drain", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, sent)
        self.assertEqual(sent["depth"]["sent"], 1)

    def test_remote_http_requires_explicit_development_opt_in(self):
        with self.assertRaises(Exception) as raised:
            agent_cli._base_url("http://10.0.0.12:8766", False)
        self.assertEqual(raised.exception.code, "transport.tls_required")
        self.assertEqual(agent_cli._base_url("http://10.0.0.12:8766", True), "http://10.0.0.12:8766")

    def test_cli_rejects_nonfinite_delivery_settings(self):
        for flag, value in (("--timeout", "nan"), ("--interval", "inf"), ("--limit", "257")):
            with self.subTest(flag=flag, value=value):
                rc, result = self._run("drain", flag, value, "--state-dir", self.alice_path)
                self.assertEqual(rc, 2)
                self.assertEqual(result["error"]["code"], "schema.invalid")

    def test_pairing_code_can_start_with_dash(self):
        rc, result = self._run("approve", "unknown-peer", "--code", "-abcdefghijk", "--state-dir", self.alice_path)
        self.assertEqual(rc, 2)
        self.assertEqual(result["error"]["code"], "auth.pairing_not_found")

    def test_cli_bounds_payload_file_and_watch_logs_only_activity(self):
        payload = self.root / "large.json"
        payload.write_bytes(b" " * (agent_cli.MAX_INLINE_BYTES + 1))
        rc, result = self._run("send", "peer", "--kind", "heartbeat", "--payload-file", str(payload), "--state-dir", self.alice_path)
        self.assertEqual(rc, 2)
        self.assertEqual(result["error"]["code"], "resource.too_large")

        stdout = io.StringIO()
        with patch.object(agent_cli.time, "sleep", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(stdout):
            code = agent_cli.main(["drain", "--watch", "--state-dir", self.alice_path])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "")


    def test_connect_inspect_ping_disconnect_and_reapprove(self):
        rc, pending = self._run("connect", self.bob_url, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, pending)
        self.assertEqual(pending["state"], "pending")
        self.assertTrue(pending["approval_required"])
        rc, info = self._run("inspect", self.bob_url, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, info)
        self.assertFalse(info["trusted"])
        self.assertEqual(info["peer_id"], self.bob.identity.system_id)
        rc, denied = self._run("ping", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 2, denied)
        self.assertEqual(denied["error"]["code"], "auth.not_paired")
        rc, other = self._run("connect", self.alice_url, "--state-dir", self.bob_path)
        self.assertEqual(rc, 0, other)
        self.assertEqual(pending["pair_code"], other["pair_code"])
        for path, peer_id in ((self.alice_path, self.bob.identity.system_id), (self.bob_path, self.alice.identity.system_id)):
            rc, approved = self._run("approve", peer_id, "--code", pending["pair_code"], "--scope", "observe.", "--state-dir", path)
            self.assertEqual(rc, 0, approved)
        rc, pong = self._run("ping", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, pong)
        self.assertEqual(pong["response"]["type"], "heartbeat")
        rc, info = self._run("inspect", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, info)
        self.assertTrue(info["trusted"])
        rc, status = self._run("status", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, status)
        self.assertEqual(status["peers"]["paired"], 1)
        rc, result = self._run("disconnect", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, result)
        self.assertTrue(result["revoked"])
        rc, denied = self._run("ping", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 2, denied)
        self.assertEqual(denied["error"]["code"], "auth.peer_revoked")

    def test_scan_caches_identity_and_connect_by_discovered_id(self):
        import fasp_harness.discovery as discovery

        card = self.bob.id_card()
        found = {"address": "127.0.0.1", "port": 8862, "scheme": "http", "card": card, "discovered_at": card["issued_at"]}
        def fake_discover(cidr, port, timeout, workers, state_dir, **kwargs):
            from fasp_harness.core import JsonState
            state = JsonState(state_dir)
            state.put("discovered.json", {card["system_id"]: found})
            return [found]
        with patch.object(discovery, "discover", side_effect=fake_discover):
            rc, result = self._run("scan", "--cidr", "127.0.0.0/30", "--port", "8862", "--scheme", "http", "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, result)
        self.assertEqual(result["count"], 1)
        self.assertFalse(result["devices"][0]["trusted"])
        rc, connected = self._run("connect", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 0, connected)
        self.assertEqual(connected["state"], "pending")

    def test_scan_scope_tls_and_identity_pin_fail_closed(self):
        rc, error = self._run("scan", "--cidr", "8.8.8.0/30", "--state-dir", self.alice_path)
        self.assertEqual(rc, 2)
        self.assertEqual(error["error"]["code"], "policy.discovery_scope")
        rc, error = self._run("scan", "--cidr", "192.168.1.0/30", "--scheme", "http", "--state-dir", self.alice_path)
        self.assertEqual(rc, 2)
        self.assertEqual(error["error"]["code"], "transport.tls_required")
        rc, error = self._run("connect", "http://10.0.0.55:8766", "--state-dir", self.alice_path)
        self.assertEqual(rc, 2)
        self.assertEqual(error["error"]["code"], "transport.tls_required")
        self._run("connect", self.bob_url, "--state-dir", self.alice_path)
        original_network = self._network

        def swapped_profile(url, payload, args):
            if url.endswith("/profile"):
                return self.alice.id_card()
            return original_network(url, payload, args)

        with patch.object(self, "_network", side_effect=swapped_profile):
            rc, error = self._run("inspect", self.bob.identity.system_id, "--state-dir", self.alice_path)
        self.assertEqual(rc, 2)
        self.assertEqual(error["error"]["code"], "auth.peer_identity_changed")


if __name__ == "__main__":
    unittest.main()
