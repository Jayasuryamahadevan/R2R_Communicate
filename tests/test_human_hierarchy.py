"""Named CLI routing uses the existing signed, durable FASP task path."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fasp_harness import agent_cli
from fasp_harness.core import FaspHarness


class HumanHierarchyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "alice"
        self.alice = FaspHarness(self.state, "alice", "http://127.0.0.1:8766")
        self.bob = FaspHarness(Path(self.temp.name) / "bob", "bob", "http://127.0.0.1:8767")
        self.addCleanup(self.alice.close)
        self.addCleanup(self.bob.close)
        a = self.alice.hello(self.bob.id_card())
        b = self.bob.hello(self.alice.id_card())
        self.assertEqual(a["pair_code"], b["pair_code"])
        self.alice.confirm_peer(self.bob.identity.system_id, a["pair_code"])
        self.bob.confirm_peer(self.alice.identity.system_id, b["pair_code"])

    def run_cli(self, *args: str) -> tuple[int, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = agent_cli.main([*args, "--state-dir", str(self.state)])
        return code, stdout.getvalue().strip() or stderr.getvalue().strip()

    def test_named_task_is_signed_queued_and_visible(self) -> None:
        code, result = self.run_cli("route", "add", "agent.researcher", self.bob.identity.system_id)
        self.assertEqual(code, 0, result)
        self.assertEqual(json.loads(result)["name"], "agent.researcher")

        code, result = self.run_cli("speak", "agent.researcher.summarize", "--message", "Summarize this", "--idempotency-key", "job-1", "--queue-only")
        self.assertEqual(code, 0, result)
        queued = json.loads(result)
        self.assertEqual(queued["task_path"], "agent.researcher.summarize")
        self.assertEqual(queued["peer_id"], self.bob.identity.system_id)
        row = self.alice.db.read_one("SELECT envelope_json FROM outbox WHERE message_id = ?", (queued["message_id"],))
        envelope = json.loads(row["envelope_json"])
        self.assertEqual(envelope["payload"]["task_name"], "summarize")
        self.assertEqual(envelope["payload"]["objective"], "Summarize this")
        self.assertEqual(envelope["payload"]["idempotency_key"], "job-1")
        FaspHarness.verify_id_card(self.alice.id_card())
        self.assertEqual(envelope["to"], self.bob.identity.system_id)
        duplicate, accepted = self.bob.accept(envelope)
        self.assertFalse(duplicate)
        self.assertEqual(accepted["output"]["summary"], "Summarize this")

        code, result = self.run_cli("tasks")
        self.assertEqual(code, 0, result)
        self.assertEqual(json.loads(result)["tasks"][0]["task_path"], "agent.researcher.summarize")
        code, result = self.run_cli("task-cancel", "agent.researcher", "job-1", "--queue-only")
        self.assertEqual(code, 0, result)
        self.assertEqual(json.loads(result)["peer_id"], self.bob.identity.system_id)

    def test_names_do_not_bypass_pairing_or_silently_change_target(self) -> None:
        code, result = self.run_cli("route", "add", "agent.researcher", self.bob.identity.system_id)
        self.assertEqual(code, 0, result)
        code, result = self.run_cli("route", "add", "agent.researcher", self.alice.identity.system_id)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(result)["error"]["code"], "auth.not_paired")
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://127.0.0.1:8768")
        self.addCleanup(carol.close)
        hello = self.alice.hello(carol.id_card())
        self.alice.confirm_peer(carol.identity.system_id, hello["pair_code"])
        code, result = self.run_cli("route", "add", "agent.researcher", carol.identity.system_id)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(result)["error"]["code"], "config.route_exists")
        code, result = self.run_cli("speak", "agent.unknown.summarize", "--message", "hello", "--queue-only")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(result)["error"]["code"], "config.route_missing")

    def test_human_output_and_json_override(self) -> None:
        code, result = self.run_cli("--human", "route", "add", "agent.researcher", self.bob.identity.system_id)
        self.assertEqual(code, 0, result)
        code, result = self.run_cli("--human", "route", "list")
        self.assertEqual(code, 0, result)
        self.assertIn("agent.researcher ->", result)
        code, result = self.run_cli("--json", "route", "list")
        self.assertEqual(code, 0, result)
        self.assertEqual(json.loads(result)["routes"][0]["name"], "agent.researcher")

    def test_connect_can_name_pending_peer_without_granting_access(self) -> None:
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://127.0.0.1:8768")
        self.addCleanup(carol.close)
        info = {"id_card": carol.id_card(), "url": "http://127.0.0.1:8768"}
        with patch.object(agent_cli, "inspect_device", return_value=info), patch.object(agent_cli, "request_json", return_value=carol.hello(self.alice.id_card())):
            code, result = self.run_cli("connect", "http://127.0.0.1:8768", "--as", "agent.writer")
        self.assertEqual(code, 0, result)
        connected = json.loads(result)
        self.assertEqual(connected["route"], "agent.writer")
        self.assertEqual(connected["state"], "pending")
        code, result = self.run_cli("say", "agent.writer", "draft", "--queue-only")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(result)["error"]["code"], "auth.not_paired")

    def test_signed_card_can_pair_without_direct_network(self) -> None:
        carol = FaspHarness(Path(self.temp.name) / "carol", "carol", "http://127.0.0.1:8768")
        self.addCleanup(carol.close)
        card_file = Path(self.temp.name) / "carol-card.json"
        card_file.write_text(json.dumps(carol.id_card()), encoding="utf-8")
        code, result = self.run_cli("import-card", str(card_file), "--as", "agent.writer")
        self.assertEqual(code, 0, result)
        self.assertEqual(json.loads(result)["state"], "pending")
        self.assertEqual(self.alice.peers.get(carol.identity.system_id)["card"]["relay_public_key"], carol.relay_key.public_b64)
        altered = carol.id_card()
        altered["display_name"] = "impostor"
        card_file.write_text(json.dumps(altered), encoding="utf-8")
        code, result = self.run_cli("import-card", str(card_file), "--as", "agent.impostor")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(result)["error"]["code"], "auth.invalid_signature")


if __name__ == "__main__":
    unittest.main()
