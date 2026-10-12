"""Optional process-supervised, stateless local adapter execution.

This provides a killable per-invocation process boundary and structured
results; it is NOT an OS sandbox. Deploy behind cgroups/seccomp/containers
and network/secret isolation. Long-running hardware adapters that require
persistent in-memory state should use a separately supervised service.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import signal
import subprocess
import sys
import threading
from typing import Any

from .protocol.errors import FaspError

MAX_INPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
CAPABILITY_TIMEOUT_S = 10.0
MAX_EXECUTION_TIMEOUT_S = 300.0


class ProcessAdapter:
    """Run a locally configured, stateless adapter in a fresh child process."""

    def __init__(self, reference: str) -> None:
        if ":" not in reference:
            raise FaspError("schema.invalid", "Process adapter must be module:factory.")
        self.reference = reference
        self._lock = threading.RLock()
        self._active: dict[str, subprocess.Popen[bytes]] = {}
        capabilities = self._execute("capabilities", None, CAPABILITY_TIMEOUT_S)
        if not isinstance(capabilities, list):
            raise FaspError("schema.invalid", "Adapter did not declare a capability list.")
        self._caps = capabilities

    def capabilities(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._caps)

    def _command(self, mode: str) -> list[str]:
        return [sys.executable, "-m", "fasp_harness.adapter_worker", "--adapter", self.reference, "--mode", mode]

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    def _execute(self, mode: str, intent: dict[str, Any] | None, timeout: float) -> Any:
        payload = json.dumps(intent, ensure_ascii=False, allow_nan=False).encode("utf-8") if intent is not None else b""
        if len(payload) > MAX_INPUT_BYTES:
            raise FaspError("resource.too_large", "Adapter input exceeds 64 KiB.")
        key = intent.get("idempotency_key") if intent is not None else None
        proc = subprocess.Popen(
            self._command(mode), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, start_new_session=os.name == "posix",
        )
        if isinstance(key, str):
            with self._lock:
                self._active[key] = proc
        try:
            try:
                output, _ = proc.communicate(payload, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                self._kill(proc)
                proc.communicate()
                raise FaspError("internal.adapter_timeout", "Adapter subprocess exceeded its allowed execution time.") from exc
            if proc.returncode != 0 or len(output) > MAX_OUTPUT_BYTES:
                raise FaspError("internal.adapter_error", "Adapter subprocess failed or exceeded its output limit.")
            try:
                message = json.loads(output)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise FaspError("internal.adapter_error", "Adapter subprocess returned an invalid response.") from exc
            if not isinstance(message, dict) or message.get("ok") is not True:
                raise FaspError("internal.adapter_error", "Adapter subprocess did not return a successful response.")
            return message.get("value")
        finally:
            if isinstance(key, str):
                with self._lock:
                    if self._active.get(key) is proc:
                        self._active.pop(key, None)

    def handle(self, intent: dict[str, Any]) -> dict[str, Any]:
        capability = intent.get("capability")
        declaration = next((item for item in self._caps if item.get("id") == capability), None)
        if declaration is None:
            raise FaspError("capability.unavailable", "Process adapter does not expose this capability.")
        runtime = declaration.get("max_runtime_s", 30.0)
        if isinstance(runtime, bool) or not isinstance(runtime, (int, float)) or not math.isfinite(runtime) or runtime <= 0:
            raise FaspError("schema.invalid", "Adapter must declare a finite, positive runtime.")
        result = self._execute("handle", intent, min(float(runtime), MAX_EXECUTION_TIMEOUT_S))
        if not isinstance(result, dict):
            raise FaspError("internal.adapter_error", "Adapter output must be a JSON object.")
        return result

    def cancel(self, idempotency_key: str) -> bool:
        with self._lock:
            process = self._active.get(idempotency_key)
            if process is None or process.poll() is not None:
                return False
            self._kill(process)
            return True


def main() -> None:
    parser = argparse.ArgumentParser(description="One-shot FASP local adapter worker.")
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--mode", choices=["capabilities", "handle"], required=True)
    args = parser.parse_args()
    from .transport.asgi_server import load_adapter

    adapter = load_adapter(args.adapter)
    if args.mode == "capabilities":
        value = adapter.capabilities()
    else:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise SystemExit(2)
        intent = json.loads(raw)
        if not isinstance(intent, dict):
            raise SystemExit(2)
        value = adapter.handle(intent)
    data = json.dumps({"ok": True, "value": value}, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(data) > MAX_OUTPUT_BYTES:
        raise SystemExit(2)
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
