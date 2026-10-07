"""One-shot verification service.

Runs three stages, in order:
  1. code tests    -- the unit test suite under tests/
  2. build checks  -- every module compiles and the server imports cleanly
  3. smoke tests   -- fixed-length and chunked audits against the live API

Exits 0 when every stage passes, 1 otherwise.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import pathlib
import sys
import time
import unittest
import urllib.error
import urllib.request

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8080").rstrip("/")


# ---------------------------------------------------------------- stage 1
def run_code_tests() -> bool:
    suite = unittest.TestLoader().discover("tests", top_level_dir=".")
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
    for line in stream.getvalue().splitlines():
        print(f"[verify]   {line}", flush=True)
    print(f"[verify] code tests: {result.testsRun} run, "
          f"{len(result.failures)} failures, {len(result.errors)} errors",
          flush=True)
    return result.wasSuccessful()


# ---------------------------------------------------------------- stage 2
def run_build_checks() -> bool:
    ok = True
    for package in ("app", "tests", "verify"):
        for path in sorted(pathlib.Path(package).rglob("*.py")):
            try:
                compile(path.read_bytes(), str(path), "exec")
            except SyntaxError as exc:
                print(f"[verify] build check FAILED: {exc}", flush=True)
                ok = False
    try:
        import app.parser  # noqa: F401
        import app.server  # noqa: F401
    except Exception as exc:
        print(f"[verify] build check FAILED: import error: {exc!r}", flush=True)
        ok = False
    if ok:
        print("[verify] build checks passed (compile + import)", flush=True)
    return ok


# ---------------------------------------------------------------- stage 3
def _post_capture(raw: bytes) -> tuple[int, dict]:
    envelope = json.dumps(
        {"captureBase64": base64.b64encode(raw).decode("ascii")}).encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}/api/http1/audit", data=envelope,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _post_raw(payload: bytes) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"{API_BASE}/api/http1/audit", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _wait_for_api(timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{API_BASE}/healthz", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except OSError:
            time.sleep(0.5)
    return False


def run_smoke_tests() -> bool:
    failures: list[str] = []

    def check(label: str, cond: bool, extra: str = "") -> None:
        if cond:
            print(f"[verify] smoke ok:   {label}", flush=True)
        else:
            print(f"[verify] smoke FAIL: {label} {extra}", flush=True)
            failures.append(label)

    if not _wait_for_api():
        print("[verify] smoke FAIL: API did not become healthy", flush=True)
        return False
    print("[verify] smoke ok:   health endpoint", flush=True)

    # -- fixed-length (Content-Length) happy path -------------------------
    body = b"hello world"
    raw = (b"POST /api/http1/audit?mode=sync HTTP/1.1\r\n"
           b"Host: gateway.internal\r\n"
           b"Content-Length: 11\r\n"
           b"\r\n" + body)
    status, doc = _post_capture(raw)
    check("fixed-length status", status == 200, f"got {status}: {doc}")
    check("fixed-length verdict", doc.get("ok") is True, str(doc))
    check("fixed-length framing", doc.get("framing") == "content-length", str(doc))
    check("fixed-length method", doc.get("method") == "POST", str(doc))
    check("fixed-length target",
          doc.get("target") == "/api/http1/audit?mode=sync", str(doc))
    check("fixed-length host", doc.get("host") == "gateway.internal", str(doc))
    check("fixed-length bodyLength", doc.get("bodyLength") == 11, str(doc))
    check("fixed-length sha256",
          doc.get("bodySha256") == hashlib.sha256(body).hexdigest(), str(doc))
    check("fixed-length trailers", doc.get("trailers") == [], str(doc))

    # -- chunked happy path with declared trailers ------------------------
    body = b"hello chunked world"
    raw = (b"POST /chunked HTTP/1.1\r\n"
           b"Host: gateway.internal\r\n"
           b"Trailer: X-Checksum, X-Origin\r\n"
           b"Transfer-Encoding: chunked\r\n"
           b"\r\n"
           b"6\r\nhello \r\n"
           b"7\r\nchunked\r\n"
           b"6\r\n world\r\n"
           b"0\r\n"
           b"X-Checksum: 0123abcd\r\n"
           b"X-Origin: edge-7\r\n"
           b"\r\n")
    status, doc = _post_capture(raw)
    check("chunked status", status == 200, f"got {status}: {doc}")
    check("chunked verdict", doc.get("ok") is True, str(doc))
    check("chunked framing", doc.get("framing") == "chunked", str(doc))
    check("chunked bodyLength", doc.get("bodyLength") == len(body), str(doc))
    check("chunked sha256",
          doc.get("bodySha256") == hashlib.sha256(body).hexdigest(), str(doc))
    check("chunked trailers ordered",
          doc.get("trailers") == [{"name": "X-Checksum", "value": "0123abcd"},
                                  {"name": "X-Origin", "value": "edge-7"}],
          str(doc))

    # -- negative: ambiguous framing (Content-Length + Transfer-Encoding) --
    raw = (b"POST /x HTTP/1.1\r\n"
           b"Host: h\r\n"
           b"Content-Length: 3\r\n"
           b"Transfer-Encoding: chunked\r\n"
           b"\r\n0\r\n\r\n")
    status, doc = _post_capture(raw)
    check("ambiguous status", status == 422, f"got {status}: {doc}")
    check("ambiguous code", doc.get("error") == "AMBIGUOUS_FRAMING", str(doc))
    check("ambiguous offset", doc.get("offset") == raw.index(b"Content-Length"),
          str(doc))

    # -- negative: bad chunk (chunk extension) -----------------------------
    raw = (b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"4;evil=1\r\nWiki\r\n0\r\n\r\n")
    status, doc = _post_capture(raw)
    check("bad chunk status", status == 422, f"got {status}: {doc}")
    check("bad chunk code", doc.get("error") == "BAD_CHUNK", str(doc))
    check("bad chunk offset", doc.get("offset") == raw.index(b";"), str(doc))

    # -- negative: illegal trailer (not declared by Trailer) ---------------
    raw = (b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"0\r\nX-Evil: 1\r\n\r\n")
    status, doc = _post_capture(raw)
    check("illegal trailer status", status == 422, f"got {status}: {doc}")
    check("illegal trailer code", doc.get("error") == "ILLEGAL_TRAILER", str(doc))
    check("illegal trailer offset", doc.get("offset") == raw.index(b"X-Evil"),
          str(doc))

    # -- negative: trailing bytes after fixed-length body ------------------
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nabc"
    status, doc = _post_capture(raw)
    check("trailing status", status == 422, f"got {status}: {doc}")
    check("trailing code", doc.get("error") == "TRAILING_BYTES", str(doc))
    check("trailing offset", doc.get("offset") == len(raw) - 1, str(doc))

    # -- negative: decoded capture over 256 KiB -----------------------------
    status, doc = _post_capture(b"A" * (256 * 1024 + 1))
    check("oversize status", status == 413, f"got {status}: {doc}")
    check("oversize code", doc.get("error") == "MESSAGE_TOO_LARGE", str(doc))

    # -- negative: invalid base64 envelope ----------------------------------
    status, doc = _post_raw(b'{"captureBase64": "!!!not-base64!!!"}')
    check("invalid base64 status", status == 400, f"got {status}: {doc}")
    check("invalid base64 code", doc.get("error") == "INVALID_BASE64", str(doc))

    return not failures


# ------------------------------------------------------------------- main
def main() -> int:
    stages = [
        ("code tests", run_code_tests),
        ("build checks", run_build_checks),
        ("smoke tests", run_smoke_tests),
    ]
    results = []
    for name, fn in stages:
        print(f"[verify] === {name} ===", flush=True)
        try:
            ok = fn()
        except Exception as exc:
            print(f"[verify] {name} raised: {exc!r}", flush=True)
            ok = False
        results.append((name, ok))
    print("[verify] === summary ===", flush=True)
    for name, ok in results:
        print(f"[verify] {name}: {'PASS' if ok else 'FAIL'}", flush=True)
    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"[verify] FAILED: {', '.join(failed)}", flush=True)
        return 1
    print("[verify] ALL CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
