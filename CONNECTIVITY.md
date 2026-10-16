# Connectivity: Wi-Fi, Ethernet, Bluetooth and REST

FASP messages have one signed JSON envelope and one receiver authorization
path. Wi-Fi and Ethernet carry the existing HTTPS/WebSocket API. Linux
Bluetooth Classic carries the same requests over RFCOMM; Bluetooth Low Energy
(BLE) carries them over an L2CAP credit based channel. Neither Bluetooth
bearer is a GATT UART service.

For other links and middleware, see the researched
[communication catalog](COMMUNICATION_CATALOG.md). It maps each source to a
canonical packet, leased stream, or optional one-time artifact reference.

| Link | Runtime | Address used by sender | Listener option |
|:--|:--|:--|:--|
| Wi-Fi / Ethernet | Any supported Python | HTTPS URL and TCP port | `--host`, `--port`, `--public-url` |
| Bluetooth Classic | Linux and BlueZ | Bluetooth address and RFCOMM channel | `--rfcomm-channel` |
| BLE | Linux, BlueZ, Python 3.14+ | Bluetooth address, LE address type and PSM | `--ble-psm`, `--ble-address-type` |
| Cross-NAT relay | Any supported Python | Pinned peer ID and outbound HTTPS hub | `--relay-worker` |

The default radio channel is 8 and default LE_PSM is `0x0080`. Those values
must match at both ends. A radio listener runs inside the same node process
as the REST API and uses the same node state, adapter, pairing records, grants,
replay journal, and metrics. When enabled, a failed radio listener fails
`/livez`. The radio listener is opt-in; the container does not have Bluetooth
device access by default.

For nodes without an inbound IP path, use the [outbound relay setup](AGENT_CLI.md#outbound-relay-across-nat).
The relay requires a reachable HTTPS hub and explicit offline pairing; it
stores signed ciphertext, with bounded retention and optional static
forwarding across up to four hubs.

## Wi-Fi or direct Ethernet

Connect the two machines to an IP network. A direct Ethernet cable works once
both have addresses on the same subnet. Use the *reachable* Wi-Fi/Ethernet
address or DNS name in `--public-url`, and a certificate valid for that name.
On the receiving node:

```bash
fasp init --name pi --state-dir ~/.fasp-pi \
  --base-url https://pi.example.internal:8766
fasp serve --name pi --state-dir ~/.fasp-pi \
  --host 0.0.0.0 --port 8766 \
  --public-url https://pi.example.internal:8766 \
  --tls-cert /path/to/pi.crt --tls-key /path/to/pi.key
```

From the sender, use `fasp register https://pi.example.internal:8766`
with `--ca-cert` if needed. Register in the other direction too, compare the
reported fingerprint, and run `fasp approve` on both nodes. See
[AGENT_CLI.md](AGENT_CLI.md) for the complete trust workflow. The same
HTTPS URL works over Wi-Fi, Ethernet, or a private IP tunnel; FASP does not
configure a wireless network or select an interface for the OS.

To discover signed cards on your own LAN, specify the CIDR and HTTPS trust
root. Discovery does not approve peers or create authority:

```bash
python -m fasp_harness discover --cidr 192.168.1.0/24 \
  --port 8766 --scheme https --ca-cert /path/to/ca.crt \
  --state-dir ~/.fasp-pi
```

The scanner probes only the requested subnet and fixed card path. It will
not follow redirects; scans above 1,024 hosts require `--allow-large`, and
the absolute limit is 65,536 addresses. IPv6 CIDRs are accepted too.

## Bluetooth Classic and BLE

First pair the *operating systems* with BlueZ on the two Linux machines.
Run `bluetoothctl` on each machine, `power on`, `pairable on`, and use
`scan bredr` for Classic or `scan le` for BLE. On the receiving machine,
turn on `discoverable on` while pairing; for BLE also use `advertise on`.
Run `pair ADDRESS` and compare the Bluetooth pairing passkey on both
machines. Restrict discoverable and pairable modes again after pairing.
BlueZ's [bluetoothctl guide](https://github.com/bluez/bluez/blob/master/doc/bluetoothctl.rst)
documents these commands.

Run the receiving FASP node with the required bearer(s):

```bash
fasp serve --name pi --state-dir ~/.fasp-pi \
  --host 0.0.0.0 --port 8766 \
  --public-url https://pi.example.internal:8766 \
  --tls-cert /path/to/pi.crt --tls-key /path/to/pi.key \
  --rfcomm-channel 8 --ble-psm 0x0080
```

If the node only needs a local REST listener, use `--host 127.0.0.1` and
omit the TLS and public URL flags. The signed ID card will then advertise
that local HTTP endpoint; radio clients use the Bluetooth address supplied
at registration.

On the sender, after `fasp init`:

```bash
# Pick one bearer. Repeat registration on the other node with its peer address.
fasp radio-register AA:BB:CC:DD:EE:FF --mode classic \
  --channel 8 --state-dir ~/.fasp-sender

# Or use BLE on Python 3.14+; choose random when BlueZ reports a random LE address.
fasp radio-register AA:BB:CC:DD:EE:FF --mode ble \
  --psm 0x0080 --address-type public --state-dir ~/.fasp-sender
```

The reply is a *pending* FASP relationship. Compare its FASP fingerprint
out of band, then run `fasp approve PEER_ID --code CODE --scope coordinate.`
on both machines. Bluetooth pairing alone does not grant FASP capabilities.

Send via radio explicitly, or omit `--transport` to use radio when no HTTP
endpoint is registered for that peer:

```bash
fasp communicate PEER_ID --message 'Status?' \
  --transport radio --state-dir ~/.fasp-sender
fasp drain --watch --transport radio --state-dir ~/.fasp-sender
```

The sender fetches and verifies the peer's signed card against its pinned
identity before every radio delivery. Bluetooth connections require BlueZ
`BT_SECURITY_HIGH` (authenticated encryption), then FASP verifies the
envelope signature, recipient, expiry, pairing, and scope. Requests are
limited to 64 KiB and responses to 2 MiB; radio workers are bounded to
eight concurrent connections. BLE packets are divided into 128-byte chunks.
This is suited to coordination messages, not continuous media or large
artifacts. Exact radio range, throughput, and LE address stability depend
on adapters, kernel, BlueZ, and local RF conditions; validate those on the
deployed hardware. A BLE GATT-only phone client needs a separate bridge or
an application that supports LE L2CAP channels.

## REST API

`GET /openapi.json` exposes the machine-readable OpenAPI 3.1 description.
`GET /profile` and `GET /.well-known/fasp/id-card.json` return the signed
public card. `POST /pair/hello` requests pending pairing. `POST
/fasp/v1/envelopes` accepts a paired, signed envelope. Protected operator
routes require the private `X-FASP-Admin-Token` header; never send that token
as a URL parameter. The WebSocket path `/fasp/v1/channel` accepts the same
signed envelopes and can push task outcomes.

```bash
curl --cacert /path/to/ca.crt \
  https://pi.example.internal:8766/openapi.json
curl --cacert /path/to/ca.crt \
  https://pi.example.internal:8766/profile
```

Use `fasp send` or the Python harness to construct signed envelopes. A bare
JSON POST is rejected: the REST path deliberately does not bypass peer
authentication or capability policy.
