"""Assert that OpenCode actually used FASP MCP, rather than only describing it."""

from __future__ import annotations

import json
import sys
from pathlib import Path

events = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
capability = sys.argv[2]
expected_tool = sys.argv[3] if len(sys.argv) > 3 else "fasp_communicate"
matched = []
for event in events:
    part = event.get("part", {})
    if not isinstance(part, dict) or part.get("type") != "tool":
        continue
    name = part.get("tool", "")
    state = part.get("state", {})
    arguments = state.get("input", {}) if isinstance(state, dict) else {}
    if name == expected_tool and isinstance(arguments, dict) and (expected_tool != "fasp_communicate" or arguments.get("capability") == capability):
        matched.append((name, state))

assert matched, f"No FASP MCP {expected_tool} event for {capability}; event types: {[event.get('type') for event in events]}"
completed = [(name, state) for name, state in matched if state.get("status") == "completed"]
assert completed, f"FASP MCP tool did not complete: {matched}"
name, state = completed[-1]
output = state.get("output")
if isinstance(output, str):
    try:
        output = json.loads(output)
    except json.JSONDecodeError:
        pass
assert isinstance(output, dict) and output.get("state") == "sent", f"FASP delivery was not sent: {output}"
receipt = output.get("response", {})
assert receipt.get("type") == "receipt.delivered", f"No FASP delivery receipt: {receipt}"
result = receipt.get("response", {}).get("output", {})
assert isinstance(result, dict) and result.get("model") == "fasp_point_robot", result
print(f"PASS OpenCode used {name} for {capability}; MuJoCo response: {json.dumps(result, sort_keys=True)}")
