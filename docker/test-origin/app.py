"""0C.9: the proxy-correctness test origin.

Records what it actually received - client address, forwarded headers,
Host, scheme, body size and upgrade negotiation - so every proxy claim
is verified by observation rather than by reading configuration. The 0D
tenant-vhost verification (0D.3) reads these observations.

std-lib only: the origin must never be a moving dependency target.
"""

import json
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_OBSERVATIONS = 100

_observations = deque(maxlen=MAX_OBSERVATIONS)
_lock = threading.Lock()


def _record(entry):
    with _lock:
        _observations.append(entry)


class RecordingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record_and_respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        entry = {
            "method": self.command,
            "path": self.path,
            "scheme": self.headers.get("X-Forwarded-Proto", "http"),
            "host": self.headers.get("Host"),
            "client_address": self.client_address[0],
            "client_port": self.client_address[1],
            "x_forwarded_for": self.headers.get("X-Forwarded-For"),
            "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
            "x_real_ip": self.headers.get("X-Real-IP"),
            "body_bytes": length,
            "upgrade": self.headers.get("Upgrade"),
            "connection": self.headers.get("Connection"),
        }
        _record(entry)
        payload = json.dumps({"recorded": True, "observation": entry}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _dispatch(self):
        if self.path == "/observations":
            with _lock:
                payload = json.dumps({"observations": list(_observations)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/health":
            payload = b'{"status": "ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self._record_and_respond()

    do_GET = do_POST = do_PUT = _dispatch

    def log_message(self, format, *args):
        pass


def run():
    server = ThreadingHTTPServer(("0.0.0.0", 8090), RecordingHandler)
    server.serve_forever()


if __name__ == "__main__":
    run()
