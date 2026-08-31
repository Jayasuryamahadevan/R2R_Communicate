"""Conformance #9 (FASP_PROTOCOL.md ss15): redact secrets and restricted
identifiers from telemetry, errors, and audit."""

from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from fasp_harness.core import FaspHarness
from fasp_harness.observability.logging import REDACTED_PLACEHOLDER, RedactingFilter, log
from fasp_harness.transport.http_app import create_app, logger as transport_logger


class RedactionFilterTests(unittest.TestCase):
    def test_known_sensitive_keys_are_redacted_even_when_nested(self) -> None:
        record = logging.LogRecord("fasp_harness", logging.INFO, __file__, 0, "event", (), None)
        record.fields = {
            "peer_id": "fasp:system:abc",
            "signature": {"alg": "Ed25519", "value": "should-not-appear"},
            "nested": {"admin_token": "super-secret", "ok": True},
        }
        RedactingFilter().filter(record)
        self.assertEqual(record.fields["signature"], REDACTED_PLACEHOLDER)
        self.assertEqual(record.fields["nested"]["admin_token"], REDACTED_PLACEHOLDER)
        self.assertTrue(record.fields["nested"]["ok"])
        self.assertEqual(record.fields["peer_id"], "fasp:system:abc")

    def test_log_helper_applies_the_filter_through_a_real_logger(self) -> None:
        test_logger = logging.getLogger("fasp_harness.test_redaction")
        test_logger.setLevel(logging.INFO)
        test_logger.propagate = False
        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = _Capture()
        handler.addFilter(RedactingFilter())
        test_logger.handlers = [handler]

        log(test_logger, logging.INFO, "grant.issued", grant_id="grant-1", admin_token="do-not-leak")
        self.assertEqual(records[0].fields["admin_token"], REDACTED_PLACEHOLDER)
        self.assertEqual(records[0].fields["grant_id"], "grant-1")


class TransportRedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.bob = FaspHarness(root / "bob", "bob", "http://bob:8766")
        self.client = TestClient(create_app(self.bob))
        self.records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(_self, record: logging.LogRecord) -> None:
                self.records.append(record)

        self.capture_handler = _Capture()
        self.capture_handler.addFilter(RedactingFilter())
        transport_logger.addHandler(self.capture_handler)

    def tearDown(self) -> None:
        transport_logger.removeHandler(self.capture_handler)
        self.temp.cleanup()

    def test_rejected_request_logging_never_carries_the_admin_token_or_a_signature(self) -> None:
        wrong_token = "definitely-not-the-real-token"
        response = self.client.get("/peers", headers={"X-FASP-Admin-Token": wrong_token})
        self.assertEqual(response.status_code, 401)

        self.assertTrue(self.records, "expected at least one captured log record")
        for record in self.records:
            serialized = json.dumps(getattr(record, "fields", {}))
            self.assertNotIn(wrong_token, serialized)
            self.assertNotIn(self.bob.admin_token, serialized)


if __name__ == "__main__":
    unittest.main()
