#!/usr/bin/env bash
# Exercise two independent node identities over a private Docker network.
set -euo pipefail

image="${1:-fasp-harness:local}"
suffix="$$"
network="fasp-smoke-$suffix"
alice="fasp-smoke-alice-$suffix"
bob="fasp-smoke-bob-$suffix"
alice_volume="fasp-smoke-alice-state-$suffix"
bob_volume="fasp-smoke-bob-state-$suffix"
results="$(mktemp -d)"
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
docker run --rm -v "$alice_volume:/home/fasp/.fasp" "$image" init --name Alice --state-dir /home/fasp/.fasp >/dev/null
docker run --rm -v "$bob_volume:/home/fasp/.fasp" "$image" init --name Bob --state-dir /home/fasp/.fasp >/dev/null
docker run -d --name "$alice" --network "$network" --network-alias fasp-a -v "$alice_volume:/home/fasp/.fasp" "$image" serve --name Alice --state-dir /home/fasp/.fasp --host 0.0.0.0 --port 8766 --public-url http://fasp-a:8766 --insecure-http >/dev/null
docker run -d --name "$bob" --network "$network" --network-alias fasp-b -v "$bob_volume:/home/fasp/.fasp" "$image" serve --name Bob --state-dir /home/fasp/.fasp --host 0.0.0.0 --port 8766 --public-url http://fasp-b:8766 --insecure-http >/dev/null

ready=0
for attempt in {1..30}; do
  if docker exec "$alice" python -c 'import urllib.request; urllib.request.urlopen("http://fasp-b:8766/health", timeout=1)' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" != 1 ]]; then
  printf 'Bob did not become reachable from Alice.\n' >&2
  exit 1
fi

docker exec "$alice" python -m fasp_harness register http://fasp-b:8766 --state-dir /home/fasp/.fasp --insecure-http > "$results/alice.json"
docker exec "$bob" python -m fasp_harness register http://fasp-a:8766 --state-dir /home/fasp/.fasp --insecure-http > "$results/bob.json"
read -r alice_code bob_id < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["pair_code"],x["peer_id"])' "$results/alice.json")
read -r bob_code alice_id < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["pair_code"],x["peer_id"])' "$results/bob.json")
[[ "$alice_code" == "$bob_code" ]]
docker exec "$alice" python -m fasp_harness approve "$bob_id" --code="$alice_code" --state-dir /home/fasp/.fasp >/dev/null
docker exec "$bob" python -m fasp_harness approve "$alice_id" --code="$alice_code" --state-dir /home/fasp/.fasp >/dev/null
docker exec "$alice" python -m fasp_harness communicate "$bob_id" --message 'container round trip' --state-dir /home/fasp/.fasp --insecure-http > "$results/delivery.json"
python3 - "$results/delivery.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
assert result["state"] == "sent", result
assert result["response"]["type"] == "receipt.delivered", result
assert result["response"]["response"]["output"]["summary"] == "container round trip", result
print("Two containers: pairing and signed delivery succeeded.")
PY
