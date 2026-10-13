# Worked example

`node.json` is a complete, runnable deployment description: a simulated
safety controller, two declared Layer 1 safety functions, one simulated
fleet with two vehicles, a site map with a blocked region, and an
active/standby leader lease.

```bash
python -m fasp_harness safety-case --config examples/node.json
python -m fasp_harness security-report --config examples/node.json
python -m fasp_harness posture --config examples/node.json --profile production
```

To drive it:

```python
from pathlib import Path
from fasp_harness.deployment import NodeConfig, build_node
from fasp_harness.fleet.model import Mission

node = build_node(NodeConfig.from_file(Path("examples/node.json")))
node.start_loops()

# Refused by the twin: the straight route from `start` to `charger` crosses
# the blocked region declared in `blocked_regions`. Raises
# `policy.preflight_failed`, and no robot is ever told about it.
node.missions.submit(Mission.from_dict(
    {"mission_id": "m1", "steps": [{"kind": "move", "node_id": "charger"}]},
    requested_by="local-operator"))

# Feasible: 20m down a clear aisle. Dispatched, with the predicted route
# reserved in space and time for its predicted arrival windows.
print(node.missions.submit(Mission.from_dict(
    {"mission_id": "m2", "steps": [{"kind": "move", "node_id": "dock-7"}]},
    requested_by="local-operator")))
```

Two things this example is **not**: the simulated safety controller carries
no safety integrity (the `production` posture check and the safety case
both refuse it, deliberately), and the simulated fleet is a test double.
Swap `{"kind": "simulated"}` for `{"kind": "modbus", "host": ...}` and a
`vda5050` or `rest` fleet to point the same coordinator at real equipment.

## Local microscope preview

`microscope_viewer.py` serves a UVC camera's MJPEG feed to a browser on the
same laptop. It uses the system Python with PyGObject and GStreamer, and does
not publish camera frames through FASP.

Find the camera under `/dev/v4l/by-id/`, then run with its stable `video-index0`
path (replace the example path with your camera's):

```bash
/usr/bin/python3 examples/microscope_viewer.py \
  --device /dev/v4l/by-id/usb-TP_C2CMOS05100KPB_01.00.00-video-index0
```

Open `http://127.0.0.1:8765/`. The defaults are 1296×972 at 50 fps; use
`--width`, `--height`, and `--fps` to select another mode advertised by the
camera. The page shows connection status, retries if the USB camera drops,
and has a **Capture photo** link. If the camera is connected but the image is
black, check its illumination, lens cap, and microscope camera light path.
Repeated USB disconnects in the kernel log call for checking the data cable,
port, and any USB hub. Press Ctrl+C to stop the stream. On Debian or Ubuntu, the system
packages `python3-gi`, `gir1.2-gstreamer-1.0`, `gstreamer1.0-plugins-base`,
and `gstreamer1.0-plugins-good` provide the required bindings and plugins.
