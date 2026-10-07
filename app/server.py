"""HTTP API for the offline HTTP/1.1 request adjudicator.

Endpoints
---------
``POST /api/http1/audit``
    JSON body ``{"captureBase64": "<base64>"}``.  Returns the verdict as JSON.

``GET /healthz`` (also ``GET /``)
    liveness probe used by the container healthcheck.

The server uses only the Python standard library, binds ``0.0.0.0:8080`` by
default and honours the ``PORT`` environment variable.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.parser import MAX_CAPTURE, VerdictError, adjudicate

#: Error codes that mean the JSON request itself was malformed (HTTP 400).
_BAD_REQUEST_CODES = {
    "invalid_json",
    "missing_field",
    "invalid_base64",
    "payload_too_large",
    "empty_message",
}

#: Base64 of the 256 KiB capture cap plus JSON envelope overhead, rounded up.
MAX_ENVELOPE = 384 * 1024


def audit_payload(raw: bytes) -> tuple[int, dict]:
    """Validate the API envelope and adjudicate the decoded capture."""
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 400, {"ok": False, "error": "invalid_json", "offset": None}
    if not isinstance(envelope, dict) or "captureBase64" not in envelope:
        return 400, {"ok": False, "error": "missing_field", "offset": None}
    encoded = envelope["captureBase64"]
    if not isinstance(encoded, str):
        return 400, {"ok": False, "error": "invalid_base64", "offset": None}
    try:
        capture = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return 400, {"ok": False, "error": "invalid_base64", "offset": None}
    if len(capture) > MAX_CAPTURE:
        return 400, {"ok": False, "error": "payload_too_large", "offset": None}
    try:
        verdict = adjudicate(capture)
    except VerdictError as exc:
        status = 400 if exc.code in _BAD_REQUEST_CODES else 422
        return status, {"ok": False, "error": exc.code, "offset": exc.offset}
    return 200, verdict


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "Http1Audit/1.0"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib naming
        if self.path in ("/healthz", "/"):
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):  # noqa: N802 - stdlib naming
        if self.path != "/api/http1/audit":
            self._send_json(404, {"ok": False, "error": "not_found"})
            return
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            self._send_json(411, {"ok": False, "error": "length_required"})
            return
        if int(length) > MAX_ENVELOPE:
            self._send_json(413, {"ok": False, "error": "envelope_too_large"})
            return
        raw = self.rfile.read(int(length))
        status, payload = audit_payload(raw)
        self._send_json(status, payload)

    def log_message(self, fmt, *args):  # keep container logs quiet
        return


def create_server(port: int | None = None) -> ThreadingHTTPServer:
    port = port if port is not None else int(os.environ.get("PORT", "8080"))
    return ThreadingHTTPServer(("0.0.0.0", port), AuditHandler)


def main() -> None:
    server = create_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
