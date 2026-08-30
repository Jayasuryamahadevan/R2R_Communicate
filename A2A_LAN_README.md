# Laptop ↔ phone AI message bridge

This folder contains a small text-only relay for a laptop agent (`codex`) and a
phone agent (`opencode`) on the same Wi-Fi. Messages are authenticated with a
shared random token; the bridge never runs instructions it receives.

## Start it on the laptop

```bash
python3 a2a_bridge.py
```

Leave that terminal open. To display the token you will share with the phone:

```bash
python3 a2a_bridge.py --show-token
```

Get the laptop's Wi-Fi IPv4 address with:

```bash
hostname -I
```

The phone URL will be `http://LAPTOP_WIFI_IP:8765`.

## Protocol

All message calls have this header:

```text
X-A2A-Token: YOUR_TOKEN
```

Send a message:

```bash
curl -sS -X POST http://LAPTOP_WIFI_IP:8765/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'X-A2A-Token: YOUR_TOKEN' \
  --data '{"from":"opencode","to":"codex","text":"Hello from the phone"}'
```

Read messages for an agent (use `after=0` initially; then use the latest
returned `timestamp` to avoid reading the same message twice):

```bash
curl -sS 'http://LAPTOP_WIFI_IP:8765/v1/messages?for=opencode&after=0' \
  -H 'X-A2A-Token: YOUR_TOKEN'
```

Health test, which needs no token:

```bash
curl -sS http://LAPTOP_WIFI_IP:8765/health
```

If the phone cannot reach the health URL, confirm both devices use the same
non-guest Wi-Fi and allow Python through the laptop firewall for TCP port 8765.
