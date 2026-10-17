#!/usr/bin/env bash
# Live /proc telemetry through two independently paired Docker nodes.
set -euo pipefail

image="${1:-fasp-harness:local}"
suffix="$$"
network="fasp-live-$suffix"
alice="fasp-live-alice-$suffix"
bob="fasp-live-bob-$suffix"
alice_volume="fasp-live-alice-state-$suffix"
bob_volume="fasp-live-bob-state-$suffix"
results="$(mktemp -d)"
scripts="$(cd "$(dirname "$0")" && pwd)"
chmod 755 "$results"

cleanup() {
  docker rm -f "$alice" "$bob" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$alice_volume" "$bob_volume" >/dev/null 2>&1 || true
  rm -rf "$results"
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker volume create "$alice_volume" >/dev/null
docker volume create "$bob_volume" >/dev/null
docker run --rm -v "$alice_volume:/home/fasp/.fasp" "$image" init --name Alice --state-dir /home/fasp/.fasp > "$results/init-a.json"
docker run --rm -v "$bob_volume:/home/fasp/.fasp" "$image" init --name Bob --state-dir /home/fasp/.fasp > "$results/init-b.json"
docker run --rm -v "$alice_volume:/home/fasp/.fasp" "$image" init --name Observer --state-dir /home/fasp/.fasp/observer > "$results/init-observer.json"
python3 - "$results/init-a.json" "$results/init-observer.json" "$results/bob-config.json" <<'PY'
import json, sys
alice_id = json.load(open(sys.argv[1]))['system_id']
observer_id = json.load(open(sys.argv[2]))['system_id']
config = {'name': 'Bob', 'stream_sharing': [{
    'capability': 'observe.stream.v1', 'peer_ids': [alice_id],
    'purposes': ['host-telemetry-test'],
    'fields': ['cpu_jiffies', 'mem_available_kb', 'uptime_s', 'observed_at_utc'],
    'content_types': ['application/json'], 'delivery_modes': ['reliable', 'latest'],
    'max_rate_hz': 10, 'max_duration_s': 90, 'max_payload_bytes': 1024,
    'max_window': 8, 'max_retention_packets': 16, 'forward_to': [observer_id],
}]}
open(sys.argv[3], 'w').write(json.dumps(config))
PY

docker run -d --name "$alice" --network "$network" --network-alias fasp-a \
  -v "$alice_volume:/home/fasp/.fasp" -v "$results:/test:ro" -v "$scripts:/scripts:ro" \
  --mount type=bind,src=/proc/stat,dst=/host-stat,readonly \
  --mount type=bind,src=/proc/meminfo,dst=/host-meminfo,readonly \
  --mount type=bind,src=/proc/uptime,dst=/host-uptime,readonly \
  "$image" serve --name Alice --state-dir /home/fasp/.fasp --host 0.0.0.0 --port 8766 \
  --public-url http://fasp-a:8766 --insecure-http >/dev/null
docker run -d --name "$bob" --network "$network" --network-alias fasp-b \
  -v "$bob_volume:/home/fasp/.fasp" -v "$results:/test:ro" -v "$scripts:/scripts:ro" \
  "$image" serve --name Bob --state-dir /home/fasp/.fasp --host 0.0.0.0 --port 8766 \
  --public-url http://fasp-b:8766 --insecure-http --config /test/bob-config.json >/dev/null

ready=0
for attempt in {1..50}; do
  if docker exec "$alice" python -c 'import urllib.request; urllib.request.urlopen("http://fasp-b:8766/health", timeout=1)' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" != 1 ]]; then
  docker logs "$bob" >&2
  echo 'Bob did not become reachable from Alice.' >&2
  exit 1
fi

docker exec "$alice" python -m fasp_harness register http://fasp-b:8766 --state-dir /home/fasp/.fasp --insecure-http > "$results/reg-a.json"
docker exec "$bob" python -m fasp_harness register http://fasp-a:8766 --state-dir /home/fasp/.fasp --insecure-http > "$results/reg-b.json"
read -r code bob_id < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["pair_code"],x["peer_id"])' "$results/reg-a.json")
read -r other_code alice_id < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["pair_code"],x["peer_id"])' "$results/reg-b.json")
[[ "$code" == "$other_code" ]]
docker exec "$alice" python -m fasp_harness approve "$bob_id" --code="$code" --scope observe. --state-dir /home/fasp/.fasp >/dev/null
docker exec "$bob" python -m fasp_harness approve "$alice_id" --code="$code" --scope observe. --state-dir /home/fasp/.fasp >/dev/null

# The observer is a separate identity housed in Alice's container. Only two
# long-running Docker containers are used, while a third peer tests push/pull.
docker exec "$alice" python -c '
import json, pathlib, urllib.request
from fasp_harness.core import FaspHarness
h = FaspHarness(pathlib.Path("/home/fasp/.fasp/observer"), "Observer", "http://fasp-a:8766")
try:
    with urllib.request.urlopen("http://fasp-b:8766/profile", timeout=5) as response:
        card = json.load(response)
    h.verify_id_card(card)
    body = json.dumps({"id_card": h.id_card()}).encode()
    request = urllib.request.Request("http://fasp-b:8766/pair/hello", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        remote = json.load(response)
    local = h.hello(card)
    assert local["pair_code"] == remote["pair_code"]
    h.confirm_peer(card["system_id"], local["pair_code"], ["observe."])
    print(json.dumps({"observer_id": h.identity.system_id, "pair_code": local["pair_code"]}))
finally:
    h.close()
' > "$results/observer-pair.json"
read -r observer_id observer_code < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["observer_id"],x["pair_code"])' "$results/observer-pair.json")
docker exec "$bob" python -m fasp_harness approve "$observer_id" --code="$observer_code" --scope observe. --state-dir /home/fasp/.fasp >/dev/null

docker exec "$bob" python -c '
import json, pathlib, sys, urllib.request
token = pathlib.Path("/home/fasp/.fasp/admin_token").read_text().strip()
body = json.dumps({"subject_peer": sys.argv[1], "capability_prefixes": ["observe.stream.v1"], "duration_seconds": 180, "purpose": "host-telemetry-test"}).encode()
request = urllib.request.Request("http://127.0.0.1:8766/grants/issue", data=body, headers={"Content-Type": "application/json", "X-FASP-Admin-Token": token})
with urllib.request.urlopen(request, timeout=5) as response:
    print(response.read().decode())
' "$alice_id" > "$results/grant.json"
docker exec "$bob" python -c '
import json, pathlib, sys, urllib.request
token = pathlib.Path("/home/fasp/.fasp/admin_token").read_text().strip()
body = json.dumps({"subject_peer": sys.argv[1], "capability_prefixes": ["observe.stream.v1"], "duration_seconds": 180, "purpose": "host-telemetry-test"}).encode()
request = urllib.request.Request("http://127.0.0.1:8766/grants/issue", data=body, headers={"Content-Type": "application/json", "X-FASP-Admin-Token": token})
with urllib.request.urlopen(request, timeout=5) as response:
    print(response.read().decode())
' "$observer_id" > "$results/observer-grant.json"

docker exec "$alice" python /scripts/container_live_stream_client.py > "$results/client.json"
docker exec "$bob" python /scripts/container_live_stream_inspect.py
docker restart "$bob" >/dev/null
ready=0
for attempt in {1..50}; do
  if docker exec "$alice" python -c 'import urllib.request; urllib.request.urlopen("http://fasp-b:8766/health", timeout=1)' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" != 1 ]]; then
  docker logs "$bob" >&2
  echo 'Bob did not recover after restart.' >&2
  exit 1
fi
docker exec "$alice" python /scripts/container_live_stream_resume.py
python3 - "$results/client.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
print('PASS 5 HTTP and 5 WebSocket reliable live packets, plus 2 latest WebSocket packets')
print('PASS', x['push_count'], 'signed WebSocket pushes to observer and', x['pulled_count'], 'packets replayed by stream.pull')
print('PASS negative checks:', ', '.join(x['negative_checks']))
print('Protocol round-trip time, 10 reliable packets (ms): min', x['round_trip_ms_min'], 'avg', x['round_trip_ms_avg'], 'max', x['round_trip_ms_max'])
print('First/last host CPU jiffies:', x['reliable_readings'][0]['cpu_jiffies'], x['reliable_readings'][-1]['cpu_jiffies'])
print('First/last host uptime (s):', x['reliable_readings'][0]['uptime_s'], x['reliable_readings'][-1]['uptime_s'])
PY
