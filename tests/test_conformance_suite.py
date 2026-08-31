"""Index of FASP_PROTOCOL.md ss15's ten conformance requirements to the test
module(s) that demonstrate each one. This file asserts nothing new -- it
exists so "does this harness pass ss15?" has one place to look, and so a
future change that deletes one of these test modules without replacing its
coverage is easy to notice.
"""

from __future__ import annotations

import importlib
import unittest

CONFORMANCE_INDEX: dict[int, tuple[str, str]] = {
    1: ("test_core", "Rejects an unsigned, expired, wrong-audience, malformed, or replayed envelope."),
    2: ("test_policy_conformance", "Rejects a validly signed request lacking a matching grant."),
    3: ("test_task_lifecycle", "Demonstrates idempotent duplicate intent handling without repeating effect."),
    4: ("test_receipts", "Distinguishes relay receipt, recipient delivery, application processing, and terminal completion."),
    5: ("test_durability", "Survives restart without skipping an accepted message or replaying a completed effect."),
    6: ("test_task_lifecycle", "Expires a task/stream lease into a safe terminal state."),
    7: ("test_cancellation", "Implements cancellation-before-effect and cancellation-too-late cases."),
    8: ("test_limits", "Enforces message, queue, rate, and artifact limits."),
    9: ("test_redaction", "Redacts secrets and restricted identifiers from telemetry, errors, and audit."),
    10: ("test_revocation", "Demonstrates key revocation and re-pairing."),
}


class ConformanceSuiteIndexTests(unittest.TestCase):
    def test_every_indexed_module_still_exists_and_is_importable(self) -> None:
        for requirement_number, (module_name, _description) in CONFORMANCE_INDEX.items():
            with self.subTest(requirement=requirement_number, module=module_name):
                importlib.import_module(module_name)

    def test_all_ten_ss15_requirements_are_indexed(self) -> None:
        self.assertEqual(sorted(CONFORMANCE_INDEX), list(range(1, 11)))


if __name__ == "__main__":
    unittest.main()
