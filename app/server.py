"""HTTP API exposing the HTTP/1.1 message-boundary adjudicator.

Routes:
  GET  /healthz           liveness probe
  POST /api/http1/audit   adjudicate one base64-encoded raw HTTP/1.1 request
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.parser import MAX_CAPTURE_BYTES, AuditError, audit

AUDIT_PATH = "/api/http1/audit"
HEALTH_PATH = "/healthz"
MAX_ENVELOPE_BYTES = 1024 * 1024  # generous bound for the JSON envelope


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "Http1Audit/1.0"
    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, doc: dict) -> None:
        payload = json.dumps(doc).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, code: str, offset: int, detail: str) -> None:
        self._send_json(status, {
            "ok": False,
            "error": code,
            "offset": offset,
            "detail": detail,
        })

    def do_GET(self) -> None:
        if self.path == HEALTH_PATH:
            self._send_json(200, {"status": "ok"})
        else:
            self._error(404, "NOT_FOUND", 0, f"no such route: {self.path}")

    def do_POST(self) -> None:
        if self.path != AUDIT_PATH:
            self._error(404, "NOT_FOUND", 0, f"no such route: {self.path}")
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._error(411, "BAD_API_REQUEST", 0, "a Content-Length is required")
            return
        if length > MAX_ENVELOPE_BYTES:
            self._error(413, "BAD_API_REQUEST", 0, "JSON envelope too large")
            return
        envelope = self.rfile.read(length)
        try:
            doc = json.loads(envelope)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "BAD_API_REQUEST", 0, "body must be a JSON object")
            return
        if not isinstance(doc, dict) or not isinstance(doc.get("captureBase64"), str):
            self._error(400, "BAD_API_REQUEST", 0,
                        'expected {"captureBase64": "<base64>"}')
            return
        try:
            capture = base64.b64decode(doc["captureBase64"], validate=True)
        except (binascii.Error, ValueError):
            self._error(400, "INVALID_BASE64", 0,
                        "captureBase64 is not valid base64")
            return
        if len(capture) > MAX_CAPTURE_BYTES:
            self._error(413, "MESSAGE_TOO_LARGE", MAX_CAPTURE_BYTES,
                        "decoded capture exceeds 256 KiB")
            return
        try:
            verdict = audit(capture)
        except AuditError as exc:
            self._error(422, exc.code, exc.offset, exc.detail)
            return
        self._send_json(200, {"ok": True, **verdict})


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), AuditHandler)
    print(f"http1-audit listening on 0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
