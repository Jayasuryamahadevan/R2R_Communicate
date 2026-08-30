"""Convenience entry point: python -m fasp_harness serve|discover."""

from __future__ import annotations

import sys

from . import discovery, server


if len(sys.argv) > 1 and sys.argv[1] == "discover":
    sys.argv.pop(1)
    discovery.main()
else:
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        sys.argv.pop(1)
    server.main()
