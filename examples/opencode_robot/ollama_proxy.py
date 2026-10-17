"""Local diagnostic proxy that records tool names sent by OpenCode to Ollama."""

from __future__ import annotations

import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


LOG = Path("/work/ollama-http.jsonl")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.forward()

    def do_POST(self) -> None:
        self.forward()

    def forward(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.command == "POST":
            try:
                request = json.loads(body)
                tools = request.get("tools", [])
                names = [tool.get("function", {}).get("name") for tool in tools]
                record = {"path": self.path, "model": request.get("model"),
                          "tools": names, "tool_choice": request.get("tool_choice"),
                          "message_roles": [message.get("role") for message in request.get("messages", [])]}
                with LOG.open("a") as stream:
                    stream.write(json.dumps(record) + "\n")
            except (ValueError, AttributeError, TypeError):
                pass
        connection = http.client.HTTPConnection("127.0.0.1", 11436, timeout=300)
        headers = {"Content-Type": self.headers.get("Content-Type", "application/json")}
        connection.request(self.command, self.path, body=body if self.command == "POST" else None, headers=headers)
        response = connection.getresponse()
        data = response.read()
        self.send_response(response.status)
        self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        connection.close()


ThreadingHTTPServer(("127.0.0.1", 11434), Handler).serve_forever()
