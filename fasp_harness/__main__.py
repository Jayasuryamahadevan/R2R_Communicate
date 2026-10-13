"""Entry point: `python -m fasp_harness <command>`.

`serve` and `discover` keep their own argument parsers (they predate the
others and their flags are load bearing for existing deployments); every
other command lives in `cli.py`. Bare `python -m fasp_harness` still starts
a server, unchanged, so nothing that already runs this needs to change.
"""

from __future__ import annotations

import sys

from . import agent_cli, cli, discovery
from .transport import asgi_server

INDUSTRIAL_COMMANDS = {"rt-probe", "layers", "safety-case", "security-report", "posture", "sbom", "hil", "zones", "guard-budget"}


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if command == "discover":
        sys.argv.pop(1)
        discovery.main()
        return 0
    if command in INDUSTRIAL_COMMANDS:
        return cli.main(sys.argv[1:])
    if command in agent_cli.AGENT_COMMANDS:
        return agent_cli.main(sys.argv[1:])
    if command == "mcp":
        from .mcp_server import main as mcp_main

        return mcp_main(sys.argv[2:])
    if command in {"-h", "--help", "help"}:
        cli.build_parser().print_help()
        print("\nAgent commands: init, register, approve, peers, communicate, send, drain, outbox, task-status.")
        print("Also available: serve (the default), discover, mcp. Run `python -m fasp_harness serve --help` for server options.")
        return 0
    if command == "serve":
        sys.argv.pop(1)
    asgi_server.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
