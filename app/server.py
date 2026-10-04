"""HTTP front-end for the diagnostic-class verifier.

Endpoints:
  GET  /            review page (paste Base64 class, view per-offset states)
  GET  /health      liveness probe -> {"status": "ok"}
  POST /api/verify  {"class_b64": "...", "method": "optional-name"}
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .verifier import verify_class

MAX_CLASS_BYTES = 64 * 1024          # 64 KiB class-file limit
MAX_BODY_BYTES = 256 * 1024          # Base64 of 64 KiB is ~87.4 K chars
INDEX = Path(__file__).with_name("web") / "index.html"


def _error(offset, kind, message):
    return {"ok": False, "error": {"offset": offset, "kind": kind,
                                   "message": message}}


class Handler(BaseHTTPRequestHandler):
    server_version = "FDiagVerify/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep container logs clean
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._json(200, {"status": "ok"})
        elif path in ("/", "/index.html"):
            body = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, _error(None, "not-found", "unknown path"))

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/verify":
            self._json(404, _error(None, "not-found", "unknown path"))
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self._json(413, _error(None, "request-too-large",
                                   f"request body exceeds {MAX_BODY_BYTES} "
                                   f"bytes"))
            return
        raw = self.rfile.read(length) if length else b""
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._json(400, _error(None, "bad-request",
                                   "request body must be a JSON object"))
            return
        if not isinstance(obj, dict) or not isinstance(obj.get("class_b64"), str):
            self._json(400, _error(None, "bad-request",
                                   'missing "class_b64" string field'))
            return
        method = obj.get("method")
        if method is not None and not isinstance(method, str):
            self._json(400, _error(None, "bad-request",
                                   '"method" must be a string when given'))
            return
        b64 = "".join(obj["class_b64"].split())  # tolerate pasted line wraps
        try:
            data = base64.b64decode(b64, validate=True)
        except binascii.Error:
            self._json(400, _error(None, "invalid-base64",
                                   "class_b64 is not valid Base64"))
            return
        if len(data) > MAX_CLASS_BYTES:
            self._json(400, _error(None, "class-too-large",
                                   f"class file is {len(data)} bytes; the "
                                   f"limit is {MAX_CLASS_BYTES} bytes "
                                   f"(64 KiB)"))
            return
        self._json(200, verify_class(data, method))


def make_server(host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    srv = make_server(host, port)
    print(f"diagnostic-class verifier listening on {host}:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
