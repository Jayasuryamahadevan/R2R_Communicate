"""Exercise FASP MCP stdio and the paired MuJoCo robot without an LLM."""

from __future__ import annotations

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def delivery_value(result):
    if result.is_error:
        raise AssertionError(f"MCP tool error: {result.model_dump()}")
    if result.structured_content is not None:
        value = result.structured_content
    else:
        value = json.loads(result.content[0].text)
    if isinstance(value, dict) and "result" in value and "state" not in value:
        value = value["result"]
    assert value["state"] == "sent", value
    return value


def unpack(result):
    value = delivery_value(result)
    receipt = value["response"]
    assert receipt["type"] == "receipt.delivered", receipt
    output = receipt["response"]["output"]
    assert output["model"] == "fasp_point_robot", output
    return output


async def main() -> None:
    peer_id, grant_id = sys.argv[1:3]
    params = StdioServerParameters(
        command="python",
        args=["-m", "fasp_harness", "mcp", "--state-dir", "/home/fasp/.fasp", "--insecure-http"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert "communicate" in {tool.name for tool in tools.tools}
            before = unpack(await session.call_tool("communicate", {
                "peer_id": peer_id,
                "capability": "observe.robot.pose.v1",
                "message": "read pose",
            }))
            moved = unpack(await session.call_tool("communicate", {
                "peer_id": peer_id,
                "capability": "robot.navigate.sim.v1",
                "grant_id": grant_id,
                "message": json.dumps({"x_m": 0.3, "y_m": 0.1}),
            }))
            after = unpack(await session.call_tool("communicate", {
                "peer_id": peer_id,
                "capability": "observe.robot.pose.v1",
                "message": "read pose",
            }))
            rejected = delivery_value(await session.call_tool("communicate", {
                "peer_id": peer_id,
                "capability": "robot.navigate.sim.v1",
                "grant_id": grant_id,
                "message": json.dumps({"x_m": 2.0, "y_m": 0.0}),
            }))
    assert before["goals_completed"] == 0, before
    assert moved["goals_completed"] == 1, moved
    assert after["goals_completed"] == 1, after
    assert abs(after["x_m"] - 0.3) < 0.02 and abs(after["y_m"] - 0.1) < 0.02, after
    failure = rejected["response"]["response"]
    assert failure["type"] == "task.fail" and failure["error"]["code"] == "policy.out_of_bounds", failure
    print(json.dumps({"before": before, "navigation_result": moved, "after": after,
                      "out_of_bounds_rejected": failure["error"]["code"]}, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
