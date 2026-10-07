#!/usr/bin/env python3
"""One-shot verification job.

Runs inside the ``verify`` compose service after the API container is healthy:

1. unit tests (``unittest`` discovery over ``tests/``)
2. build check (byte-compilation of every package module)
3. live smoke tests against ``http://api:8080`` covering both fixed-length and
   chunked framing, plus representative smuggling rejections

Exits 0 only when every stage passes; the first failing stage determines the
process exit code.
"""

from __future__ import annotations

import base64
import compileall
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

API_URL = os.environ.get("API_URL", "http://api:8080").rstrip("/")
WORKSPACE = os.environ.get("WORKSPACE", "/srv")

# Running "python smoke/verify.py" puts smoke/ on sys.path; add the project
# root so the app and tests packages import the same way the unit suite does.
sys.path.insert(0, WORKSPACE)


def stage(name: str):
    print(f"\n=== verify: {name} ===", flush=True)


def run_unit_tests() -> bool:
    stage("unit tests")
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(WORKSPACE, "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


def run_build_check() -> bool:
    stage("build check (compileall)")
    ok = compileall.compile_dir(
        os.path.join(WORKSPACE, "app"), quiet=1, maxlevels=10
    )
    print("compileall: " + ("OK" if ok else "FAILED"))
    return ok


def post_capture(raw: bytes):
    body = json.dumps(
        {"captureBase64": base64.b64encode(raw).decode("ascii")}
    ).encode()
    req = urllib.request.Request(
        API_URL + "/api/http1/audit",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


FIXED = (
    b"POST /api/http1/audit HTTP/1.1\r\n"
    b"Host: gateway.local\r\n"
    b"Content-Length: 11\r\n"
    b"\r\n"
    b"hello world"
)

CHUNKED = (
    b"POST /ingest HTTP/1.1\r\n"
    b"Host: gateway.local\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Trailer: X-Checksum\r\n"
    b"\r\n"
    b"5\r\nhello\r\n"
    b"6\r\n world\r\n"
    b"0\r\n"
    b"X-Checksum: deadbeef\r\n"
    b"\r\n"
)

# (label, capture, expected HTTP status, expected error code or None)
REJECTIONS = [
    (
        "trailing bytes after fixed body",
        FIXED + b"smuggled",
        422,
        "trailing_bytes",
    ),
    (
        "CL + TE together",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n",
        422,
        "conflicting_framing",
    ),
    (
        "chunk extension",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5;evil=1\r\nhello\r\n0\r\n\r\n",
        422,
        "chunk_extension_not_allowed",
    ),
    (
        "bad chunk terminator",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhelloXX0\r\n\r\n",
        422,
        "bad_chunk_terminator",
    ),
    (
        "undeclared trailer",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"0\r\nX-Sneaky: 1\r\n\r\n",
        422,
        "undeclared_trailer",
    ),
    (
        "forbidden routing trailer",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n"
        b"Trailer: Host\r\n\r\n0\r\nHost: evil\r\n\r\n",
        422,
        "forbidden_trailer",
    ),
    (
        "bare LF line ending",
        b"POST /x HTTP/1.1\nHost: h\r\n\r\n",
        422,
        "bad_line_ending",
    ),
]


def run_smoke() -> bool:
    stage(f"live smoke against {API_URL}")
    ok = True

    with urllib.request.urlopen(API_URL + "/healthz", timeout=5) as resp:
        health = json.loads(resp.read())
    print("healthz:", resp.status, health)
    if resp.status != 200 or health.get("status") != "ok":
        ok = False

    status, verdict = post_capture(FIXED)
    print("fixed-length:", status, verdict)
    if status != 200 or verdict.get("framing") != "content-length":
        ok = False
    if verdict.get("bodyLength") != 11:
        ok = False
    if verdict.get("method") != "POST" or verdict.get("host") != "gateway.local":
        ok = False

    status, verdict = post_capture(CHUNKED)
    print("chunked:", status, verdict)
    if status != 200 or verdict.get("framing") != "chunked":
        ok = False
    if verdict.get("bodyLength") != 11:
        ok = False
    trailers = verdict.get("trailers")
    if trailers != [{"name": "X-Checksum", "value": "deadbeef"}]:
        ok = False

    for label, capture, want_status, want_code in REJECTIONS:
        status, verdict = post_capture(capture)
        code = verdict.get("error")
        offset = verdict.get("offset")
        print(f"reject [{label}]: HTTP {status} {code} @ {offset}")
        if status != want_status or code != want_code or offset is None:
            print("  -> UNEXPECTED")
            ok = False

    return ok


def main() -> int:
    stages = (
        ("unit tests", run_unit_tests),
        ("build check", run_build_check),
        ("smoke", run_smoke),
    )
    for name, fn in stages:
        if not fn():
            print(f"\nVERIFY FAILED at stage: {name}", flush=True)
            return 1
    print("\nVERIFY OK: all stages passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
