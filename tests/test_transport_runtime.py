"""Saturation, cancellation and authenticated full-duplex transport boundaries."""

from __future__ import annotations

import asyncio
import contextvars
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from fasp_harness.channels import ConnectionRegistry
from fasp_harness.core import DefaultSafeAdapter, FaspError, FaspHarness
from fasp_harness.observability.metrics import MetricsRegistry
from fasp_harness.transport.http_app import create_app
from fasp_harness.transport.runtime import ChannelSession, IngressDispatcher, TransportLimits


class IngressIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_busy_work_cannot_queue_observations_or_control(self) -> None:
        ingress = IngressDispatcher(TransportLimits(work_workers=1), MetricsRegistry())
        entered, release = threading.Event(), threading.Event()

        def blocked():
            entered.set()
            release.wait(3)
            return {"ok": True}

        work = asyncio.create_task(ingress.run({"kind": "intent.propose", "from": "a"}, blocked))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            with self.assertRaises(FaspError) as error:
                await ingress.run({"kind": "intent.propose", "from": "b"}, blocked)
            self.assertEqual(error.exception.code, "transport.overloaded")
            for kind in ("heartbeat", "task.cancel", "safety.halt"):
                result = await asyncio.wait_for(ingress.run({"kind": kind}, lambda: {"ok": True}), 1)
                self.assertTrue(result["ok"])
            self.assertFalse(release.is_set())
        finally:
            release.set()
            await work
            await asyncio.to_thread(ingress.close)

    async def test_cancellation_does_not_release_a_running_handler(self) -> None:
        ingress = IngressDispatcher(TransportLimits(work_workers=1), MetricsRegistry())
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()

        def blocked():
            entered.set()
            release.wait(3)
            finished.set()
            return {}

        task = asyncio.create_task(ingress.run({}, blocked))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            with self.assertRaises(FaspError):
                await ingress.run({}, lambda: {})
            self.assertEqual(ingress.gauges()['fasp_ingress_active{lane="work"}'], 1)
        finally:
            release.set()
            await asyncio.to_thread(ingress.close)
        self.assertTrue(finished.is_set())
        self.assertEqual(ingress.gauges()['fasp_ingress_active{lane="work"}'], 0)

    async def test_per_peer_fairness_and_request_context_survive_offload(self) -> None:
        ingress = IngressDispatcher(TransportLimits(work_workers=2, per_peer_per_lane=1), MetricsRegistry())
        entered, release = threading.Event(), threading.Event()

        def blocked():
            entered.set()
            release.wait(3)
            return {}

        task = asyncio.create_task(ingress.run({"from": "a"}, blocked))
        marker = contextvars.ContextVar("request_marker", default="missing")
        marker.set("present")
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            with self.assertRaises(FaspError):
                await ingress.run({"from": "a"}, lambda: {})
            self.assertEqual(await ingress.run({"from": "b"}, lambda: {"marker": marker.get()}), {"marker": "present"})
        finally:
            release.set()
            await task
            await asyncio.to_thread(ingress.close)

    async def test_push_and_reply_have_one_writer_and_timeout_closes_slow_push(self) -> None:
        class Socket:
            def __init__(self):
                self.entered, self.release = asyncio.Event(), asyncio.Event()
                self.active = self.maximum = self.closed = 0
                self.messages = []

            async def send_text(self, text):
                self.active += 1
                self.maximum = max(self.maximum, self.active)
                try:
                    self.entered.set()
                    await self.release.wait()
                    self.messages.append(text)
                finally:
                    self.active -= 1

            async def close(self, code):
                self.closed = code

        socket = Socket()
        session = ChannelSession(socket, 0.1)
        registry = ConnectionRegistry(send_timeout_s=0.1)
        registry.bind_loop(asyncio.get_running_loop())
        registry.register("a", session)
        direct = asyncio.create_task(session.send_json({"reply": 1}))
        await socket.entered.wait()
        self.assertTrue(registry.push("a", {"push": 1}))
        await asyncio.sleep(0.01)
        self.assertEqual(socket.maximum, 1)
        socket.release.set()
        await direct
        for _ in range(100):
            if len(socket.messages) == 2:
                break
            await asyncio.sleep(0.001)
        self.assertEqual(len(socket.messages), 2)
        socket.release.clear()
        registry.push("a", {"slow": 1})
        for _ in range(100):
            if socket.closed:
                break
            await asyncio.sleep(0.005)
        self.assertEqual(socket.closed, 1013)
        self.assertFalse(registry.is_connected("a"))


class BlockingAdapter(DefaultSafeAdapter):
    def __init__(self):
        self.entered, self.release = threading.Event(), threading.Event()

    def capabilities(self):
        return [{"id": "observe.system.status.v1", "risk": "observe", "max_runtime_s": 2, "network": "none"}]

    def handle(self, intent):
        self.entered.set()
        self.release.wait(3)
        return super().handle(intent)


class TransportBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.adapter = BlockingAdapter()
        self.alice = FaspHarness(root / "a", "a", "http://a")
        self.bob = FaspHarness(root / "b", "b", "http://b", adapter=self.adapter)
        hello = self.bob.hello(self.alice.id_card())
        self.bob.confirm_peer(self.alice.identity.system_id, hello["pair_code"])

    def tearDown(self):
        self.adapter.release.set()
        self.alice.close()
        self.bob.close()
        self.temp.cleanup()

    def envelope(self, kind="heartbeat", key="work"):
        return self.alice.make_envelope(
            kind,
            self.bob.identity.system_id,
            {"intent_id": key, "idempotency_key": key, "capability": "observe.system.status.v1", "risk": "observe"}
            if kind == "intent.propose"
            else {},
        )

    def test_http_overload_has_no_effect_and_websocket_control_still_responds(self):
        with TestClient(create_app(self.bob, transport_limits=TransportLimits(work_workers=1))) as client, ThreadPoolExecutor() as pool:
            first = pool.submit(client.post, "/fasp/v1/envelopes", json=self.envelope("intent.propose"))
            try:
                self.assertTrue(self.adapter.entered.wait(1))
                rejected = self.envelope("intent.propose", "rejected")
                response = client.post("/fasp/v1/envelopes", json=rejected)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers["Retry-After"], "1")
                self.assertEqual(response.json()["error"]["code"], "transport.overloaded")
                self.assertIsNone(self.bob.inbox.get_response(rejected["message_id"]))
                self.assertIsNone(self.bob.tasks.get("rejected"))
                with client.websocket_connect("/fasp/v1/channel") as channel:
                    request = self.envelope()
                    channel.send_json(request)
                    result = channel.receive_json()
                    self.assertEqual(result["in_reply_to"], request["message_id"])
                    self.assertEqual(result["type"], "heartbeat")
                self.assertFalse(self.adapter.release.is_set())
                metrics = client.get("/metrics", headers={"X-FASP-Admin-Token": self.bob.admin_token}).text
                self.assertIn('fasp_ingress_active{lane="work"} 1', metrics)
            finally:
                self.adapter.release.set()
                first.result(3)

    def test_socket_cannot_switch_to_another_paired_identity_before_effects(self):
        other = FaspHarness(Path(self.temp.name) / "c", "c", "http://c")
        hello = self.bob.hello(other.id_card())
        self.bob.confirm_peer(other.identity.system_id, hello["pair_code"])
        request = other.make_envelope(
            "intent.propose",
            self.bob.identity.system_id,
            {"intent_id": "switch", "idempotency_key": "switch", "capability": "observe.system.status.v1", "risk": "observe"},
        )
        try:
            with TestClient(create_app(self.bob)) as client, client.websocket_connect("/fasp/v1/channel") as channel:
                channel.send_json(self.envelope())
                channel.receive_json()
                channel.send_json(request)
                self.assertEqual(channel.receive_json()["error"]["code"], "auth.channel_identity")
                with self.assertRaises(WebSocketDisconnect) as error:
                    channel.receive_json()
                self.assertEqual(error.exception.code, 1008)
                self.assertIsNone(self.bob.tasks.get("switch"))
        finally:
            other.close()

    def test_unauthenticated_connections_are_bounded_and_expire(self):
        limits = TransportLimits(max_channels=1, auth_timeout_s=0.1)
        with TestClient(create_app(self.bob, transport_limits=limits)) as client:
            with client.websocket_connect("/fasp/v1/channel") as first:
                with self.assertRaises(WebSocketDisconnect) as error:
                    with client.websocket_connect("/fasp/v1/channel"):
                        pass
                self.assertEqual(error.exception.code, 1013)
                with self.assertRaises(WebSocketDisconnect) as error:
                    first.receive_json()
                self.assertEqual(error.exception.code, 1008)
            with client.websocket_connect("/fasp/v1/channel") as replacement:
                replacement.send_json(self.envelope())
                self.assertEqual(replacement.receive_json()["type"], "heartbeat")

    def test_repeated_invalid_frames_cannot_verify_signatures_forever(self):
        with (
            TestClient(create_app(self.bob, transport_limits=TransportLimits(max_invalid_frames=2))) as client,
            client.websocket_connect("/fasp/v1/channel") as channel,
        ):
            for _ in range(2):
                channel.send_json({"bad": True})
                self.assertEqual(channel.receive_json()["error"]["code"], "schema.invalid")
            with self.assertRaises(WebSocketDisconnect) as error:
                channel.receive_json()
            self.assertEqual(error.exception.code, 1008)

    def test_revoke_disconnects_an_idle_push_consumer(self):
        with TestClient(create_app(self.bob)) as client, client.websocket_connect("/fasp/v1/channel") as channel:
            channel.send_json(self.envelope())
            channel.receive_json()
            self.bob.revoke_peer(self.alice.identity.system_id, "revoked")
            self.assertFalse(self.bob.channels.is_connected(self.alice.identity.system_id))
            with self.assertRaises(WebSocketDisconnect):
                channel.receive_json()

    def test_push_rechecks_authority_changed_by_another_database_connection(self):
        import sqlite3

        with TestClient(create_app(self.bob)) as client, client.websocket_connect("/fasp/v1/channel") as channel:
            channel.send_json(self.envelope())
            channel.receive_json()
            with sqlite3.connect(self.bob.db.path) as connection:
                connection.execute("UPDATE peers SET expires_at='2000-01-01T00:00:00Z' WHERE peer_id=?", (self.alice.identity.system_id,))
            self.assertFalse(self.bob.channels.push(self.alice.identity.system_id, {"type": "task.push"}))
            with self.assertRaises(WebSocketDisconnect):
                channel.receive_json()


class DeadlineAndConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_http_body_is_rejected_before_decoding_or_dispatch(self):
        from starlette.requests import Request

        from fasp_harness.transport.http_app import _error_status, _read_json_body

        async def receive():
            await asyncio.sleep(1)
            return {"type": "http.request", "body": b"{}", "more_body": False}

        request = Request({"type": "http", "path": "/fasp/v1/envelopes"}, receive=receive)
        with self.assertRaises(FaspError) as error:
            await _read_json_body(request, timeout_s=0.01)
        self.assertEqual(error.exception.code, "transport.read_timeout")
        self.assertEqual(_error_status(error.exception), 408)

    async def test_invalid_limits_fail_before_starting_a_worker(self):
        for value in (0, -1, True, 65):
            with self.subTest(value=value), self.assertRaises(ValueError):
                TransportLimits(work_workers=value)
        for value in (0, -1, True, float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                TransportLimits(body_timeout_s=value)

    async def test_cli_rejects_unsafe_limits_before_creating_state(self):
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "not-created"
            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-m", "fasp_harness", "serve", "--state-dir", str(state), "--ingress-work-workers", "0"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("work_workers", result.stderr)
            self.assertFalse(state.exists())
