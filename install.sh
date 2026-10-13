#!/usr/bin/env bash
# Install the FASP node with only Python by default. Optional integrations
# are explicit so small hosts do not need Node or an agent application.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

WITH_MCP=0
WITH_BRIDGES=0
usage() {
  cat <<'HELP'
Usage: ./install.sh [--with-mcp] [--with-bridges]

Default: install the Python FASP node into .venv from uv.lock when uv is
available. --with-mcp adds a local stdio MCP server. --with-bridges installs
the separate Node integrations (requires Node 20+ and npm).
HELP
}
for arg in "$@"; do
  case "$arg" in
    --with-mcp) WITH_MCP=1 ;;
    --with-bridges) WITH_BRIDGES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
  esac
done

PYTHON_BIN=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' 2>/dev/null; then
    PYTHON_BIN="$candidate"
    break
  fi
done
if [[ -z "$PYTHON_BIN" ]]; then
  printf 'Python 3.11+ is required. Install python3 and python3-venv, then retry.\n' >&2
  exit 1
fi

if command -v uv >/dev/null 2>&1; then
  extras=()
  if [[ "$WITH_MCP" == 1 ]]; then extras=(--extra mcp); fi
  uv sync --locked --no-dev --python "$PYTHON_BIN" "${extras[@]}"
else
  if [[ ! -d .venv ]]; then "$PYTHON_BIN" -m venv .venv; fi
  if [[ ! -x .venv/bin/pip ]]; then
    printf '.venv has no pip. Install uv or recreate .venv with python3 -m venv.\n' >&2
    exit 1
  fi
  package='.'
  if [[ "$WITH_MCP" == 1 ]]; then package='.[mcp]'; fi
  .venv/bin/python -m pip install "$package"
fi

if [[ "$WITH_BRIDGES" == 1 ]]; then
  if ! command -v node >/dev/null 2>&1 || ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) < 20)' || ! command -v npm >/dev/null 2>&1; then
    printf 'The optional bridges require Node.js 20+ and npm.\n' >&2
    exit 1
  fi
  for bridge in opencode_bridge/plugin pi_bridge/extension; do
    (cd "$bridge" && npm ci --ignore-scripts)
  done
fi

printf '\nFASP installed: %s/.venv/bin/fasp\n' "$ROOT"
printf 'Next: .venv/bin/fasp init --name my-node --state-dir ~/.fasp-agent\n'
if [[ "$WITH_MCP" == 1 ]]; then
  printf 'MCP command: %s/.venv/bin/fasp mcp --state-dir ~/.fasp-agent\n' "$ROOT"
fi
