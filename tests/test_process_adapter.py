"""Optional killable process adapter tests (not an OS sandbox)."""

from __future__ import annotations

import sys
import time
import unittest

from fasp_harness.adapter_worker import ProcessAdapter
from fasp_harness.protocol.errors import FaspError


class ProcessAdapterTests(unittest.TestCase):
    def test_stateless_adapter_runs_out_of_process(self) -> None:
        adapter = ProcessAdapter("fasp_harness.example_adapter:create_adapter")
        self.assertEqual(adapter.capabilities()[0]["id"], "coordinate.plan.v1")
        outcome = adapter.handle({
            "idempotency_key": "example",
            "capability": "coordinate.plan.v1",
            "objective": "Make a safe plan",
        })
        self.assertEqual(outcome["status"], "planned")

    def test_hung_child_process_is_killed_at_runtime_deadline(self) -> None:
        adapter = ProcessAdapter("fasp_harness.example_adapter:create_adapter")
        adapter._caps[0]["max_runtime_s"] = 0.1
        adapter._command = lambda mode: [sys.executable, "-c", "import time; time.sleep(5)"]
        started = time.monotonic()
        with self.assertRaises(FaspError) as raised:
            adapter.handle({
                "idempotency_key": "hang",
                "capability": "coordinate.plan.v1",
                "objective": "a",
            })
        self.assertEqual(raised.exception.code, "internal.adapter_timeout")
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(adapter._active, {})


if __name__ == "__main__":
    unittest.main()
