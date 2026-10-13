#!/usr/bin/python3
"""Serve a local MJPEG preview of a UVC microscope camera.

Run with: /usr/bin/python3 examples/microscope_viewer.py --device /dev/video2
Requires the system's python3-gi and GStreamer V4L2 packages.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Condition, Thread

import gi

gi.require_version("Gst", "1.0")
from gi.repository import Gst  # noqa: E402


class Camera:
    def __init__(self, device: str, width: int, height: int, fps: int):
        self.condition = Condition()
        self.frame = None
        self.sequence = 0
        self.error = None

        Gst.init(None)
        self.pipeline = Gst.Pipeline.new("microscope")
        source = Gst.ElementFactory.make("v4l2src", "camera")
        caps_filter = Gst.ElementFactory.make("capsfilter", "format")
        sink = Gst.ElementFactory.make("appsink", "frames")
        if any(element is None for element in (source, caps_filter, sink)):
            raise RuntimeError("GStreamer V4L2 or app sink plugin is unavailable")

        source.set_property("device", device)
        caps_filter.set_property(
            "caps", Gst.Caps.from_string(
                f"image/jpeg,width={width},height={height},framerate={fps}/1"
            )
        )
        sink.set_property("emit-signals", True)
        sink.set_property("max-buffers", 1)
        sink.set_property("drop", True)
        sink.set_property("sync", False)
        sink.connect("new-sample", self._on_sample)
        for element in (source, caps_filter, sink):
            self.pipeline.add(element)
        if not source.link(caps_filter) or not caps_filter.link(sink):
            raise RuntimeError("Could not link the camera pipeline")

    def _on_sample(self, sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.ERROR
        buffer = sample.get_buffer()
        frame = buffer.extract_dup(0, buffer.get_size())
        with self.condition:
            self.frame = frame
            self.sequence += 1
            self.condition.notify_all()
        return Gst.FlowReturn.OK

    def start(self):
        if self.pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            raise RuntimeError("Could not start the microscope camera")
        Thread(target=self._watch_bus, daemon=True).start()
        with self.condition:
            self.condition.wait_for(
                lambda: self.frame is not None or self.error is not None, timeout=8
            )
            if self.error:
                raise RuntimeError(self.error)
            if self.frame is None:
                raise RuntimeError("No frames received; check the device and video mode")

    def _watch_bus(self):
        bus = self.pipeline.get_bus()
        message = bus.timed_pop_filtered(
            Gst.CLOCK_TIME_NONE, Gst.MessageType.ERROR | Gst.MessageType.EOS
        )
        if message:
            if message.type == Gst.MessageType.ERROR:
                error, _debug = message.parse_error()
                reason = str(error)
            else:
                reason = "Camera stream ended"
            with self.condition:
                self.error = reason
                self.condition.notify_all()
            print(f"Camera error: {reason}", flush=True)

    def stop(self):
        self.pipeline.set_state(Gst.State.NULL)


PAGE = b"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microscope live view</title>
<style>body{margin:0;background:#111;color:#eee;font:16px system-ui;text-align:center}
header{padding:12px}img{display:block;max-width:100vw;max-height:calc(100vh - 70px);margin:auto;object-fit:contain}
</style><header>Microscope live view</header><img src="/stream.mjpg" alt="Live microscope camera feed"></html>"""


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
        elif self.path == "/stream.mjpg":
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last_sequence = -1
            try:
                while True:
                    with self.camera.condition:
                        self.camera.condition.wait_for(
                            lambda: self.camera.sequence != last_sequence
                            or self.camera.error is not None,
                            timeout=5,
                        )
                        if self.camera.error:
                            break
                        frame = self.camera.frame
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
