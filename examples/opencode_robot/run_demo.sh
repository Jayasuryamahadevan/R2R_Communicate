#!/usr/bin/env bash
# Real OpenCode CLI -> local FASP MCP (stdio) -> paired FASP HTTP -> MuJoCo.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
mode=""
skip_build=0
for arg in "$@"; do
  case "$arg" in
    --skip-build) skip_build=1 ;;
    --probe-only|--human-test) mode="$arg" ;;
    *)
      echo "Unknown option: $arg" >&2
      echo 'Usage: run_demo.sh [--skip-build] [--probe-only | --human-test]' >&2
      exit 2
      ;;
  esac
done
opencode_bin="${OPENCODE_BIN:-$(command -v opencode || true)}"
ollama_bin="${OLLAMA_BIN:-$(command -v ollama || true)}"
ollama_models="${OLLAMA_MODELS_DIR:-$HOME/.ollama/models}"
model="${FASP_DEMO_MODEL:-qwen2.5:3b}"
if [[ ! -f "$opencode_bin" ]]; then
  echo 'Set OPENCODE_BIN to an installed OpenCode Linux binary.' >&2
  exit 1
fi
if [[ "$mode" != "--probe-only" && ( ! -f "$ollama_bin" || ! -d "$ollama_models" ) ]]; then
  echo 'A local Ollama binary and installed model directory are required.' >&2
  exit 1
fi

if [[ "$skip_build" != 1 ]]; then
  docker build --pull=false -t fasp-harness:local "$root" >/dev/null
  docker build --pull=false -f "$root/examples/opencode_robot/Dockerfile.opencode" -t fasp-opencode:mcp "$root/examples/opencode_robot" >/dev/null
  docker build --pull=false -f "$root/examples/opencode_robot/Dockerfile.robot" -t fasp-robot:mujoco "$root/examples/opencode_robot" >/dev/null
fi

suffix="$$"
network="fasp-oc-robot-$suffix"
opencode_container="fasp-oc-$suffix"
robot_container="fasp-robot-$suffix"
opencode_volume="fasp-oc-state-$suffix"
robot_volume="fasp-robot-state-$suffix"
work="$(mktemp -d)"
chmod 755 "$work"
cp "$root/examples/opencode_robot/probe_mcp.py" "$work/probe_mcp.py"
if [[ "$mode" == "--human-test" ]]; then
  cp "$root/examples/opencode_robot/ollama_proxy.py" "$work/ollama_proxy.py"
  touch "$work/ollama-http.jsonl"
  touch "$work/opencode-server.log"
  chmod 666 "$work/ollama-http.jsonl"
  chmod 666 "$work/opencode-server.log"
fi
cleanup() {
  if [[ "${demo_ok:-0}" != 1 ]]; then
    docker logs "$robot_container" 2>&1 | tail -35 >&2 || true
    docker logs "$opencode_container" 2>&1 | tail -35 >&2 || true
  fi
  docker rm -f "$opencode_container" "$robot_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$opencode_volume" "$robot_volume" >/dev/null 2>&1 || true
  if [[ "${demo_ok:-0}" == 1 ]]; then
    rm -rf "$work"
  else
    echo "Failed run evidence retained at: $work" >&2
  fi
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker volume create "$opencode_volume" >/dev/null
docker volume create "$robot_volume" >/dev/null
docker run --rm -v "$opencode_volume:/home/fasp/.fasp" fasp-opencode:mcp init --name OpenCode --base-url http://opencode:8766 --state-dir /home/fasp/.fasp --insecure-http > "$work/opencode-init.json"
docker run --rm -v "$robot_volume:/home/fasp/.fasp" fasp-robot:mujoco init --name MuJoCoRobot --base-url http://robot:8766 --state-dir /home/fasp/.fasp --insecure-http > "$work/robot-init.json"

cat > "$work/opencode.json" <<'JSON'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "ollama/__MODEL__",
  "providers": {
    "ollama": {
      "models": {
        "__MODEL__": {"capabilities": {"tools": true}}
      }
    }
  },
  "default_agent": "robot",
  "agents": {
    "robot": {
      "mode": "primary",
      "system": "You operate a MuJoCo robot only through the fasp_communicate MCP tool. For every request, make a native tool call before any text. Use the Qwen tool-call format: <tool_call>{\"name\":\"fasp_communicate\",\"arguments\":{\"peer_id\":\"...\",\"capability\":\"...\",\"message\":\"...\"}}</tool_call>. Fill in the exact supplied arguments. Never write Python code or a descriptive example. Never invent a tool result or robot pose."
    }
  },
  "permissions": [
    {"action": "read", "resource": "*", "effect": "deny"},
    {"action": "edit", "resource": "*", "effect": "deny"},
    {"action": "shell", "resource": "*", "effect": "deny"},
    {"action": "glob", "resource": "*", "effect": "deny"},
    {"action": "grep", "resource": "*", "effect": "deny"},
    {"action": "subagent", "resource": "*", "effect": "deny"},
    {"action": "skill", "resource": "*", "effect": "deny"},
    {"action": "question", "resource": "*", "effect": "deny"},
    {"action": "execute", "resource": "*", "effect": "deny"},
    {"action": "websearch", "resource": "*", "effect": "deny"},
    {"action": "webfetch", "resource": "*", "effect": "deny"},
    {"action": "fasp_*", "resource": "*", "effect": "deny"},
    {"action": "fasp_communicate", "resource": "*", "effect": "allow"}
  ],
  "policies": [
    {"action": "provider.use", "resource": "*", "effect": "deny"},
    {"action": "provider.use", "resource": "ollama", "effect": "allow"}
  ],
  "mcp": {
    "servers": {
      "fasp": {
        "type": "local",
        "command": ["python", "-m", "fasp_harness", "mcp", "--state-dir", "/home/fasp/.fasp", "--insecure-http"],
        "codemode": false,
        "timeout": {"startup": 20000, "request": 20000}
      }
    }
  }
}
JSON
sed -i "s|__MODEL__|$model|g" "$work/opencode.json"

docker run -d --name "$robot_container" --network "$network" --network-alias robot \
  -v "$robot_volume:/home/fasp/.fasp" fasp-robot:mujoco \
  serve --name MuJoCoRobot --state-dir /home/fasp/.fasp --host 0.0.0.0 --port 8766 \
  --public-url http://robot:8766 --insecure-http --adapter robot_adapter:factory >/dev/null
opencode_mounts=(
  -v "$opencode_volume:/home/fasp/.fasp"
  -v "$work:/work"
  -v "$opencode_bin:/usr/local/bin/opencode:ro"
  -e HOME=/tmp/fasp-home
)
if [[ "$mode" != "--probe-only" ]]; then
  opencode_mounts+=(
    -v "$ollama_bin:/usr/local/bin/ollama:ro"
    -v /usr/local/lib/ollama:/usr/local/lib/ollama:ro
    -v "$ollama_models:/home/fasp/.ollama/models:ro"
    -e OLLAMA_MODELS=/home/fasp/.ollama/models
    -e OLLAMA_HOST=127.0.0.1:11434
  )
fi
docker run -d --name "$opencode_container" --network "$network" --network-alias opencode \
  "${opencode_mounts[@]}" \
  --workdir /work \
  --entrypoint sleep fasp-opencode:mcp infinity >/dev/null
docker exec "$opencode_container" mkdir -p /tmp/fasp-home
if [[ "$mode" != "--probe-only" ]]; then
  if [[ "$mode" == "--human-test" ]]; then
    docker exec -d -e OLLAMA_HOST=127.0.0.1:11436 "$opencode_container" ollama serve
  else
    docker exec -d "$opencode_container" ollama serve
  fi
fi

ready=0
for attempt in {1..50}; do
  if docker exec "$opencode_container" python -c 'import urllib.request; urllib.request.urlopen("http://robot:8766/health", timeout=1)' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
[[ "$ready" == 1 ]] || { echo 'Robot FASP server did not become reachable.' >&2; exit 1; }
if [[ "$mode" != "--probe-only" ]]; then
  ollama_ready=0
  for attempt in {1..100}; do
    ollama_port=11434
    if [[ "$mode" == "--human-test" ]]; then ollama_port=11436; fi
    if docker exec "$opencode_container" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$ollama_port/api/tags', timeout=1)" >/dev/null 2>&1; then
      ollama_ready=1
      break
    fi
    sleep 0.2
  done
  [[ "$ollama_ready" == 1 ]] || { echo 'Local Ollama did not become reachable.' >&2; exit 1; }
fi
if [[ "$mode" == "--human-test" ]]; then
  docker exec -d "$opencode_container" python /work/ollama_proxy.py
  proxy_ready=0
  for attempt in {1..50}; do
    if docker exec "$opencode_container" python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1)' >/dev/null 2>&1; then
      proxy_ready=1
      break
    fi
    sleep 0.2
  done
  [[ "$proxy_ready" == 1 ]] || { echo 'Ollama diagnostic proxy did not become reachable.' >&2; exit 1; }
fi

docker exec "$opencode_container" python -m fasp_harness register http://robot:8766 --state-dir /home/fasp/.fasp --insecure-http > "$work/pair.json"
read -r robot_id pair_code < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["peer_id"],x["pair_code"])' "$work/pair.json")
opencode_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["system_id"])' "$work/opencode-init.json")"
docker exec "$opencode_container" python -m fasp_harness approve "$robot_id" --code="$pair_code" \
  --scope observe.robot.pose.v1 --scope robot.navigate.sim.v1 --state-dir /home/fasp/.fasp >/dev/null
docker exec "$robot_container" python -m fasp_harness approve "$opencode_id" --code="$pair_code" \
  --scope observe.robot.pose.v1 --scope robot.navigate.sim.v1 --state-dir /home/fasp/.fasp >/dev/null

docker exec "$robot_container" python -c '
import json, pathlib, sys, urllib.request
token = pathlib.Path("/home/fasp/.fasp/admin_token").read_text().strip()
body = json.dumps({"subject_peer":sys.argv[1],"capability_prefixes":["robot.navigate.sim.v1"],"duration_seconds":1800,"purpose":"mujoco-demo"}).encode()
request = urllib.request.Request("http://127.0.0.1:8766/grants/issue",data=body,headers={"Content-Type":"application/json","X-FASP-Admin-Token":token})
with urllib.request.urlopen(request,timeout=5) as response:
    print(response.read().decode())
' "$opencode_id" > "$work/grant.json"
grant_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["grant_id"])' "$work/grant.json")"

if [[ "$mode" == "--human-test" ]]; then
  python3 - "$work/opencode.json" "$robot_id" "$grant_id" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
config = json.loads(path.read_text())
config["permissions"] = [rule for rule in config["permissions"] if rule["action"] != "fasp_communicate"]
config["permissions"].append({"action": "fasp_robot_*", "resource": "*", "effect": "allow"})
config["mcp"]["servers"]["fasp"]["command"].extend([
    "--robot-peer-id", sys.argv[2], "--robot-grant-id", sys.argv[3],
])
config["agents"]["robot"]["system"] = (
    "You control one paired MuJoCo robot through two FASP MCP tools: "
    "fasp_robot_pose and fasp_robot_navigate. Use fasp_robot_pose for every "
    "position request. For a relative move, use the most recently reported "
    "pose in this conversation. The robot starts at (0, 0) metres. Add "
    "the requested offsets to x_m and y_m, then call fasp_robot_navigate "
    "with the absolute goal coordinates in metres. Do not reread the pose "
    "when the previous user turn already asked for it. Right is +x; forward is +y. "
    "The maximum single move is 0.5 m. Report only completed tool results. "
    "Never invent a pose or claim a move succeeded without a tool result."
)
config["agents"]["robot"]["steps"] = 4
path.write_text(json.dumps(config, indent=2) + "\n")
PY
  server_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  docker exec -d -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" sh -c 'opencode serve --hostname 127.0.0.1 --port 4096 > /work/opencode-server.log 2>&1'
  server_ready=0
  for attempt in {1..100}; do
    if docker exec -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" python -c '
import base64, os, urllib.request
password=os.environ["OPENCODE_SERVER_PASSWORD"]
token=base64.b64encode(("opencode:"+password).encode()).decode()
request=urllib.request.Request("http://127.0.0.1:4096/api/mcp", headers={"Authorization":"Basic "+token})
urllib.request.urlopen(request, timeout=1)
' >/dev/null 2>&1; then
      server_ready=1
      break
    fi
    sleep 0.2
  done
  [[ "$server_ready" == 1 ]] || { echo 'OpenCode server did not become reachable.' >&2; exit 1; }
fi

echo 'OpenCode MCP connection:'
mcp_status=''
for attempt in {1..20}; do
  mcp_status="$(docker exec "$opencode_container" opencode mcp list)"
  if [[ "$mcp_status" == *'fasp  connected'* ]]; then break; fi
  sleep 0.5
done
echo "$mcp_status"
[[ "$mcp_status" == *'fasp  connected'* ]] || { echo 'OpenCode did not connect to FASP MCP.' >&2; exit 1; }

if [[ "$mode" == "--probe-only" ]]; then
  echo 'Direct MCP protocol probe from inside the OpenCode container:'
  docker exec "$opencode_container" python /work/probe_mcp.py "$robot_id" "$grant_id"
elif [[ "$mode" == "--human-test" ]]; then
  docker exec "$opencode_container" opencode debug agents > "$work/opencode-agents.txt"
  if docker exec -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" opencode api --server http://127.0.0.1:4096 GET /api/model > "$work/opencode-models.json"; then
    python3 - "$work/opencode-models.json" "$model" <<'PY'
import json, sys
for model in json.load(open(sys.argv[1])).get("data", []):
    if model.get("providerID") == "ollama" and model.get("id") == sys.argv[2]:
        print("OpenCode model tool capability:", model.get("capabilities", {}).get("tools"))
PY
  fi
  docker exec -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" opencode api --server http://127.0.0.1:4096 GET /api/mcp > "$work/opencode-mcp.json"
  python3 - "$work/opencode-mcp.json" <<'PY'
import json, sys
servers = json.load(open(sys.argv[1]))["data"]
assert any(server.get("name") == "fasp" and server.get("status", {}).get("status") == "connected" for server in servers), servers
print("OpenCode server MCP: fasp connected")
PY
  docker exec -i -e DEMO_MODEL="$model" "$opencode_container" python - > "$work/ollama-tool-probe.json" <<'PY'
import json, os, urllib.request
base = "http://127.0.0.1:11434"
def post(path, body):
    request = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)
model = post("/api/show", {"model": os.environ["DEMO_MODEL"]})
chat = post("/api/chat", {
    "model": os.environ["DEMO_MODEL"], "stream": False,
    "messages": [
        {"role": "system", "content": "Use the get_pose tool to answer robot position questions. Do not invent a pose."},
        {"role": "user", "content": "Where is the robot right now?"},
    ],
    "tools": [{"type": "function", "function": {
        "name": "get_pose", "description": "Read the current robot pose",
        "parameters": {"type": "object", "properties": {}},
    }}],
    "options": {"num_ctx": 16384},
})
print(json.dumps({"model_capabilities": model.get("capabilities"), "message": chat.get("message")}, sort_keys=True))
PY
  python3 - "$work/ollama-tool-probe.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
print("Ollama native tool probe:", "tool_calls" if result["message"].get("tool_calls") else "text_only")
PY
  human_failed=0
  echo 'Human: Where is the robot right now? Tell me its position.'
  docker exec -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" opencode run --server http://127.0.0.1:4096 --auto --agent robot --model "ollama/$model" --format json \
    'Where is the robot right now? Tell me its position.' > "$work/pose-before.jsonl"
  if ! python3 "$root/examples/opencode_robot/verify_opencode_events.py" "$work/pose-before.jsonl" observe.robot.pose.v1 fasp_robot_pose; then
    human_failed=1
  fi

  echo 'Human: Move the robot 30 centimetres right and 10 centimetres forward.'
  docker exec -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" opencode run --server http://127.0.0.1:4096 --continue --auto --agent robot --model "ollama/$model" --format json \
    'Move the robot 30 centimetres right and 10 centimetres forward.' > "$work/navigate.jsonl"
  if ! python3 "$root/examples/opencode_robot/verify_opencode_events.py" "$work/navigate.jsonl" robot.navigate.sim.v1 fasp_robot_navigate; then
    human_failed=1
  fi

  echo 'Human: Where is the robot now?'
  docker exec -e OPENCODE_SERVER_PASSWORD="$server_password" "$opencode_container" opencode run --server http://127.0.0.1:4096 --continue --auto --agent robot --model "ollama/$model" --format json \
    'Where is the robot now?' > "$work/pose-after.jsonl"
  if ! python3 "$root/examples/opencode_robot/verify_opencode_events.py" "$work/pose-after.jsonl" observe.robot.pose.v1 fasp_robot_pose; then
    human_failed=1
  fi
  docker exec "$robot_container" python -c '
import pathlib
p=pathlib.Path("/home/fasp/.fasp/robot_actions.jsonl")
print("Robot action journal entries:", len(p.read_text().splitlines()) if p.exists() else 0)
'
  python3 - "$work/ollama-http.jsonl" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
for row in (json.loads(line) for line in path.read_text().splitlines() if line.strip()):
    if row["path"].startswith("/v1/chat/completions") or row["path"].startswith("/api/chat"):
        print("OpenCode model request tools:", row["tools"])
PY
  if [[ "$human_failed" == 1 ]]; then
    echo 'FAIL one or more plain-language OpenCode prompts had no verified FASP MCP result.' >&2
    exit 1
  fi
else
echo 'OpenCode asks for the robot pose:'
docker exec "$opencode_container" opencode run --standalone --auto --agent robot --model "ollama/$model" --format json \
  "Use only the fasp_communicate MCP tool. Call it with peer_id $robot_id, capability observe.robot.pose.v1, message read pose. Report the returned pose; do not invent a reading." \
  > "$work/pose-before.jsonl"
python3 "$root/examples/opencode_robot/verify_opencode_events.py" "$work/pose-before.jsonl" observe.robot.pose.v1

echo 'OpenCode requests one bounded MuJoCo goal:'
docker exec "$opencode_container" opencode run --standalone --auto --agent robot --model "ollama/$model" --format json \
  "Use only the fasp_communicate MCP tool. Call it exactly once with peer_id $robot_id, capability robot.navigate.sim.v1, grant_id $grant_id, message {\"x_m\":0.3,\"y_m\":0.1}. Report the tool result. Do not run shell commands." \
  > "$work/navigate.jsonl"
python3 "$root/examples/opencode_robot/verify_opencode_events.py" "$work/navigate.jsonl" robot.navigate.sim.v1

echo 'OpenCode asks for the final robot pose:'
docker exec "$opencode_container" opencode run --standalone --auto --agent robot --model "ollama/$model" --format json \
  "Use only the fasp_communicate MCP tool. Call it with peer_id $robot_id, capability observe.robot.pose.v1, message read pose. Report the returned x_m, y_m and goals_completed exactly." \
  > "$work/pose-after.jsonl"
python3 "$root/examples/opencode_robot/verify_opencode_events.py" "$work/pose-after.jsonl" observe.robot.pose.v1
fi

docker exec "$robot_container" python -c '
import json, pathlib
rows=[json.loads(line) for line in pathlib.Path("/home/fasp/.fasp/robot_actions.jsonl").read_text().splitlines()]
assert len(rows)==1, rows
row=rows[0]
assert row["goal"]=={"x_m":0.3,"y_m":0.1}, row
assert abs(row["result"]["x_m"]-0.3)<0.02 and abs(row["result"]["y_m"]-0.1)<0.02, row
print("PASS robot action journal:", json.dumps(row, separators=(",",":")))
'
demo_ok=1
if [[ "$mode" == "--probe-only" ]]; then
  echo 'PASS MCP stdio -> signed FASP HTTP -> MuJoCo robot -> FASP receipt -> MCP client inside OpenCode container.'
elif [[ "$mode" == "--human-test" ]]; then
  echo 'PASS human prompt -> OpenCode -> FASP MCP -> MuJoCo robot -> actual pose.'
else
  echo 'PASS OpenCode -> MCP stdio -> signed FASP HTTP -> MuJoCo robot -> FASP receipt -> MCP -> OpenCode.'
fi
