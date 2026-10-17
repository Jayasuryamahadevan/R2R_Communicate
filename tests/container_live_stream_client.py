"""Run inside the Alice container for container_live_stream.sh."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from contextlib import ExitStack
from datetime import timedelta
from pathlib import Path

from websockets.sync.client import connect

from fasp_harness.core import FaspHarness
from fasp_harness.crypto.envelope import unb64, verify
from fasp_harness.streaming import packetize
from fasp_harness.timestamps import now, stamp

ROOT = Path("/test")
STATE = Path("/home/fasp/.fasp")
URL = "http://fasp-b:8766/fasp/v1/envelopes"
CAPABILITY = "observe.stream.v1"
FIELDS = ["cpu_jiffies", "mem_available_kb", "uptime_s", "observed_at_utc"]


def http(envelope: dict) -> tuple[int, dict, float]:
    request = urllib.request.Request(URL, data=json.dumps(envelope).encode(), headers={"Content-Type": "application/json"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.load(response), (time.monotonic() - start) * 1000
    except urllib.error.HTTPError as error:
        return error.code, json.load(error), (time.monotonic() - start) * 1000


def sample() -> dict:
    cpu = Path("/host-stat").read_text().splitlines()[0].split()
    memory = next(line for line in Path("/host-meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    return {
        "cpu_jiffies": sum(map(int, cpu[1:8])),
        "mem_available_kb": int(memory.split()[1]),
        "uptime_s": float(Path("/host-uptime").read_text().split()[0]),
        "observed_at_utc": stamp(now()),
    }


def check_error(result: tuple[int, dict, float], code: str) -> None:
    status, body, _ = result
    assert status >= 400 and body.get("error", {}).get("code") == code, (status, body)


def run() -> None:
    bob_id = json.loads((ROOT / "reg-a.json").read_text())["peer_id"]
    grant = json.loads((ROOT / "grant.json").read_text())
    observer_grant = json.loads((ROOT / "observer-grant.json").read_text())
    observer_id = json.loads((ROOT / "observer-pair.json").read_text())["observer_id"]
    harness = FaspHarness(STATE, "Alice", "http://fasp-a:8766")
    observer = FaspHarness(STATE / "observer", "Observer", "http://fasp-a:8766")
    channels = ExitStack()
    observer_channel = None
    try:
        def signed(kind: str, payload: dict) -> dict:
            return harness.make_envelope(kind, bob_id, payload)

        def open_payload(delivery: str, with_grant: bool = True) -> dict:
            payload = {
                "capability": CAPABILITY,
                "purpose": "host-telemetry-test",
                "recipient": bob_id,
                "fields": FIELDS,
                "content_type": "application/json",
                "delivery": delivery,
                "max_payload_bytes": 1024,
                "window": 8,
                "max_rate_hz": 10,
                "duration_s": 90,
                "expires_at": stamp(now() + timedelta(seconds=90)),
                "retention_packets": 16,
                "forward_to": [observer_id],
            }
            if with_grant:
                payload["grant"] = {"id": grant["grant_id"], "digest": grant["digest"]}
            return payload

        check_error(http(signed("stream.open", open_payload("reliable", False))), "auth.not_authorized")
        status, opened, _ = http(signed("stream.open", open_payload("reliable")))
        assert status == 200 and opened["state"] == "open", (status, opened)
        stream_id = opened["stream_id"]

        with urllib.request.urlopen("http://fasp-b:8766/profile", timeout=5) as response:
            bob_card = json.load(response)
        observer_channel = channels.enter_context(connect("ws://fasp-b:8766/fasp/v1/channel", open_timeout=5, close_timeout=5))
        subscribed_envelope = observer.make_envelope("stream.subscribe", bob_id, {
            "capability": CAPABILITY,
            "stream_id": stream_id,
            "grant": {"id": observer_grant["grant_id"], "digest": observer_grant["digest"]},
        })
        observer_channel.send(json.dumps(subscribed_envelope))
        subscribed = json.loads(observer_channel.recv(timeout=5))
        assert subscribed["type"] == "stream.subscribed" and subscribed["stream_id"] == stream_id, subscribed

        expected = []
        latencies = []
        pushes = []

        def check_push(sequence: int, reading: dict) -> None:
            push = json.loads(observer_channel.recv(timeout=5))
            verify(push, bob_card["public_key"])
            assert push["type"] == "stream.push" and push["packet"]["sequence"] == sequence, push
            assert push["origin_peer"] == harness.identity.system_id and push["recipient_peer"] == observer_id, push
            assert json.loads(unb64(push["packet"]["payload"])) == reading, push
            pushes.append(sequence)

        def make_packet(sequence: int, reading: dict) -> dict:
            payload = json.dumps(reading, separators=(",", ":")).encode()
            packet = next(packetize(stream_id, 0, sequence, payload, "application/json", 1024))
            packet["capability"] = CAPABILITY
            return packet

        first = sample()
        packet0 = make_packet(0, first)
        status, ack, rtt = http(signed("stream.packet", packet0))
        assert status == 200 and ack["type"] == "stream.ack" and ack["ack_sequence"] == 0, (status, ack)
        expected.append(first)
        latencies.append(rtt)
        check_push(0, first)

        tampered = signed("stream.packet", make_packet(1, sample()))
        tampered["payload"]["sequence"] = 3
        check_error(http(tampered), "auth.invalid_signature")
        check_error(http(signed("stream.packet", make_packet(2, sample()))), "stream.out_of_order")
        damaged = make_packet(1, sample())
        damaged["checksum"] = "sha-256:" + "0" * 64
        check_error(http(signed("stream.packet", damaged)), "stream.checksum_mismatch")
        unauthorized = sample()
        unauthorized["undeclared_data"] = "must not cross"
        check_error(http(signed("stream.packet", make_packet(1, unauthorized))), "auth.not_authorized")
        status, duplicate, _ = http(signed("stream.packet", packet0))
        assert status == 200 and duplicate["duplicate"] is True and duplicate["ack_sequence"] == 0, duplicate
        try:
            observer_channel.recv(timeout=0.2)
        except TimeoutError:
            pass
        else:
            raise AssertionError("Duplicate packet was pushed again")

        for sequence in range(1, 5):
            time.sleep(0.12)
            reading = sample()
            status, ack, rtt = http(signed("stream.packet", make_packet(sequence, reading)))
            assert status == 200 and ack["ack_sequence"] == sequence and ack["credit"] == 8, (status, ack)
            expected.append(reading)
            latencies.append(rtt)
            check_push(sequence, reading)

        with connect("ws://fasp-b:8766/fasp/v1/channel", open_timeout=5, close_timeout=5) as channel:
            for sequence in range(5, 10):
                time.sleep(0.12)
                reading = sample()
                envelope = signed("stream.packet", make_packet(sequence, reading))
                start = time.monotonic()
                channel.send(json.dumps(envelope))
                ack = json.loads(channel.recv(timeout=5))
                latencies.append((time.monotonic() - start) * 1000)
                assert ack["type"] == "stream.ack" and ack["ack_sequence"] == sequence and ack["in_reply_to"] == envelope["message_id"], ack
                expected.append(reading)
                check_push(sequence, reading)

            latest_open = signed("stream.open", open_payload("latest"))
            channel.send(json.dumps(latest_open))
            latest = json.loads(channel.recv(timeout=5))
            assert latest["state"] == "open" and latest["in_reply_to"] == latest_open["message_id"], latest
            latest_id = latest["stream_id"]
            latest_expected = []
            for sequence in (0, 2):
                time.sleep(0.12)
                reading = sample()
                raw = json.dumps(reading, separators=(",", ":")).encode()
                frame = next(packetize(latest_id, 0, sequence, raw, "application/json", 1024))
                frame["capability"] = CAPABILITY
                channel.send(json.dumps(signed("stream.packet", frame)))
                ack = json.loads(channel.recv(timeout=5))
                assert ack["type"] == "stream.ack" and ack["ack_sequence"] == sequence, ack
                latest_expected.append({"sequence": sequence, "reading": reading})

        pulled = http(observer.make_envelope("stream.pull", bob_id, {
            "capability": CAPABILITY,
            "stream_id": stream_id,
            "after_sequence": -1,
            "grant": {"id": observer_grant["grant_id"], "digest": observer_grant["digest"]},
        }))
        assert pulled[0] == 200 and len(pulled[1]["packets"]) == 10, pulled
        for sequence, (packet, reading) in enumerate(zip(pulled[1]["packets"], expected, strict=True)):
            assert packet["sequence"] == sequence and json.loads(unb64(packet["payload"])) == reading, packet

        assert len({reading["cpu_jiffies"] for reading in expected}) > 1
        assert len({reading["uptime_s"] for reading in expected}) > 1
        status, closed, _ = http(signed("stream.close", {"capability": CAPABILITY, "stream_id": stream_id}))
        assert status == 200 and closed["type"] == "stream.closed", (status, closed)
        check_error(http(signed("stream.packet", make_packet(10, sample()))), "stream.not_open")

        print(json.dumps({
            "reliable_stream_id": stream_id,
            "latest_stream_id": latest_id,
            "reliable_readings": expected,
            "latest_readings": latest_expected,
            "http_packets": 5,
            "websocket_packets": 7,
            "push_count": len(pushes),
            "pulled_count": len(pulled[1]["packets"]),
            "round_trip_ms_min": round(min(latencies), 2),
            "round_trip_ms_max": round(max(latencies), 2),
            "round_trip_ms_avg": round(sum(latencies) / len(latencies), 2),
            "negative_checks": ["grant_required", "invalid_signature", "out_of_order", "checksum_mismatch", "undeclared_json_field", "duplicate_ack", "closed_stream"],
        }))
    finally:
        channels.close()
        observer.close()
        harness.close()


if __name__ == "__main__":
    run()
