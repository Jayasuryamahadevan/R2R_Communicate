#!/usr/bin/python3
"""Serve a local MJPEG preview of a UVC microscope camera.

Run with: /usr/bin/python3 examples/microscope_viewer.py --device /dev/video2
Requires the system's python3-gi and GStreamer V4L2 packages.
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Condition, Event, Thread

import gi

gi.require_version("Gst", "1.0")
from gi.repository import Gst  # noqa: E402


class Camera:
    def __init__(self, device: str, width: int, height: int, fps: int):
        self.device = device
        self.width = width
        self.height = height
        self.fps = fps
        self.condition = Condition()
        self.frame = None
        self.sequence = 0
        self.last_frame_at = None
        self.error = "Connecting to camera"
        self.stop_event = Event()
        self.pipeline = None

        Gst.init(None)

    def _make_pipeline(self):
        pipeline = Gst.Pipeline.new("microscope")
        source = Gst.ElementFactory.make("v4l2src", "camera")
        caps_filter = Gst.ElementFactory.make("capsfilter", "format")
        sink = Gst.ElementFactory.make("appsink", "frames")
        if any(element is None for element in (source, caps_filter, sink)):
            raise RuntimeError("GStreamer V4L2 or app sink plugin is unavailable")

        source.set_property("device", self.device)
        caps_filter.set_property(
            "caps", Gst.Caps.from_string(
                f"image/jpeg,width={self.width},height={self.height},framerate={self.fps}/1"
            )
        )
        sink.set_property("emit-signals", True)
        sink.set_property("max-buffers", 1)
        sink.set_property("drop", True)
        sink.set_property("sync", False)
        sink.connect("new-sample", self._on_sample)
        for element in (source, caps_filter, sink):
            pipeline.add(element)
        if not source.link(caps_filter) or not caps_filter.link(sink):
            raise RuntimeError("Could not link the camera pipeline")
        return pipeline

    def _on_sample(self, sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.ERROR
        buffer = sample.get_buffer()
        frame = buffer.extract_dup(0, buffer.get_size())
        with self.condition:
            self.frame = frame
            self.sequence += 1
            self.last_frame_at = time.monotonic()
            self.error = None
            self.condition.notify_all()
        return Gst.FlowReturn.OK

    def start(self):
        Thread(target=self._capture_loop, daemon=True).start()

    def _capture_loop(self):
        while not self.stop_event.is_set():
            try:
                with self.condition:
                    self.error = "Connecting to camera"
                self.pipeline = self._make_pipeline()
                if self.pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
                    raise RuntimeError("Could not start the camera")
                bus = self.pipeline.get_bus()
                started = time.monotonic()
                while not self.stop_event.is_set():
                    message = bus.timed_pop_filtered(
                        Gst.SECOND, Gst.MessageType.ERROR | Gst.MessageType.EOS
                    )
                    if message:
                        if message.type == Gst.MessageType.ERROR:
                            error, _debug = message.parse_error()
                            raise RuntimeError(str(error))
                        raise RuntimeError("Camera stream ended")
                    with self.condition:
                        last_frame_at = self.last_frame_at
                    if last_frame_at is None or last_frame_at < started:
                        if time.monotonic() - started > 8:
                            raise RuntimeError("No frames received from camera")
                    elif time.monotonic() - last_frame_at > 8:
                        raise RuntimeError("Camera stopped sending frames")
            except Exception as exc:
                reason = str(exc)
                print(f"Camera unavailable: {reason}; retrying", flush=True)
                with self.condition:
                    self.error = reason
                    self.condition.notify_all()
            finally:
                if self.pipeline is not None:
                    self.pipeline.set_state(Gst.State.NULL)
                    self.pipeline = None
            self.stop_event.wait(2)

    def status(self):
        with self.condition:
            age = (time.monotonic() - self.last_frame_at) if self.last_frame_at else None
            connected = self.error is None and age is not None and age < 5
            return {"connected": connected, "error": self.error, "frame_age_seconds": age}

    def stop(self):
        self.stop_event.set()
        if self.pipeline is not None:
            self.pipeline.set_state(Gst.State.NULL)


PAGE = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microscope live view</title>
<style>
body{margin:0;background:#111;color:#eee;font:16px system-ui;text-align:center}
header,.controls{display:flex;gap:12px;align-items:center;justify-content:center;flex-wrap:wrap;padding:8px}
a{color:#9cf}button{font:inherit;cursor:pointer}input[type=range]{width:min(220px,45vw)}
#status{min-height:24px;padding:4px}#viewport{height:calc(100vh - 145px);min-height:220px;
display:flex;align-items:center;justify-content:center;overflow:hidden;touch-action:none;cursor:grab}
#viewport.dragging{cursor:grabbing}#feed{display:block;max-width:none;max-height:none;user-select:none}
small{display:block;padding:5px;color:#aaa}
</style>
<header><strong>Microscope live view</strong><a href="/snapshot.jpg" download="microscope.jpg">Capture photo</a></header>
<div class="controls"><label for="zoom">Digital zoom</label><input id="zoom" type="range" min="1" max="8" step="0.1" value="1">
<output id="zoom-value" for="zoom">1.0&times;</output><button id="reset" type="button">Reset view</button></div>
<div id="status">Connecting to camera...</div>
<div id="viewport"><img id="feed" src="/stream.mjpg" alt="Live microscope camera feed" draggable="false"></div>
<small>Use the slider or mouse wheel to zoom; drag to pan. Capture photo saves the full camera frame.</small>
<script>
const viewport=document.getElementById('viewport'),feed=document.getElementById('feed');
const slider=document.getElementById('zoom'),value=document.getElementById('zoom-value');
let zoom=1,panX=0,panY=0,dragging=false,lastX=0,lastY=0;
function render(){
  const vw=viewport.clientWidth,vh=viewport.clientHeight;
  const ratio=(feed.naturalWidth||4)/(feed.naturalHeight||3);
  const w=Math.min(vw,vh*ratio),h=w/ratio;
  feed.style.width=w+'px';feed.style.height=h+'px';
  panX=Math.max(-Math.max(0,(w*zoom-vw)/2),Math.min(Math.max(0,(w*zoom-vw)/2),panX));
  panY=Math.max(-Math.max(0,(h*zoom-vh)/2),Math.min(Math.max(0,(h*zoom-vh)/2),panY));
  feed.style.transform=`translate(${panX}px,${panY}px) scale(${zoom})`;
  value.textContent=zoom.toFixed(1)+'×';slider.value=zoom.toFixed(1);
}
function setZoom(next){zoom=Math.max(1,Math.min(8,Number(next)));render()}
slider.addEventListener('input',()=>setZoom(slider.value));
document.getElementById('reset').addEventListener('click',()=>{zoom=1;panX=0;panY=0;render()});
viewport.addEventListener('wheel',event=>{event.preventDefault();setZoom(zoom*Math.exp(-event.deltaY/500))},{passive:false});
viewport.addEventListener('pointerdown',event=>{if(zoom===1)return;dragging=true;lastX=event.clientX;lastY=event.clientY;
  viewport.setPointerCapture(event.pointerId);viewport.classList.add('dragging')});
viewport.addEventListener('pointermove',event=>{if(!dragging)return;panX+=event.clientX-lastX;panY+=event.clientY-lastY;
  lastX=event.clientX;lastY=event.clientY;render()});
function endDrag(){dragging=false;viewport.classList.remove('dragging')}
viewport.addEventListener('pointerup',endDrag);viewport.addEventListener('pointercancel',endDrag);
feed.addEventListener('load',render);new ResizeObserver(render).observe(viewport);render();
async function update(){try{const r=await fetch('/status');const s=await r.json();
document.getElementById('status').textContent=s.connected
?'Camera connected. If the image is black, check microscope illumination and the camera light path.'
:'Camera disconnected or unavailable. Check the USB cable and port; reconnecting automatically.';
}catch{document.getElementById('status').textContent='Viewer connection lost.'}}
update();setInterval(update,1500)
</script></html>""".encode("utf-8")


class ViewerHandler(BaseHTTPRequestHandler):
    camera: Camera

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(PAGE)
        elif self.path == "/status":
            data = json.dumps(self.camera.status()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/snapshot.jpg":
            with self.camera.condition:
                frame = self.camera.frame if self.camera.error is None else None
            if frame is None:
                self.send_error(503, "Camera is unavailable")
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(frame)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(frame)
        elif self.path == "/stream.mjpg":
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last_sequence = self.camera.sequence
            try:
                while True:
                    with self.camera.condition:
                        self.camera.condition.wait_for(
                            lambda: self.camera.sequence != last_sequence,
                            timeout=5,
                        )
                        frame = self.camera.frame if self.camera.sequence != last_sequence else None
                        last_sequence = self.camera.sequence
                    if frame is not None:
                        self.wfile.write(
                            b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                            + str(len(frame)).encode()
                            + b"\r\n\r\n"
                            + frame
                            + b"\r\n"
                        )
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="V4L2 camera path")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--width", type=int, default=1296)
    parser.add_argument("--height", type=int, default=972)
    parser.add_argument("--fps", type=int, default=50)
    args = parser.parse_args()
    camera = Camera(args.device, args.width, args.height, args.fps)
    try:
        camera.start()
        ViewerHandler.camera = camera
        server = ThreadingHTTPServer(("127.0.0.1", args.port), ViewerHandler)
        server.daemon_threads = True
        print(f"Microscope live view: http://127.0.0.1:{args.port}/", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
    finally:
        camera.stop()


if __name__ == "__main__":
    main()
