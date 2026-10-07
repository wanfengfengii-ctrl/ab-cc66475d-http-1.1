"""Deterministic HTTP/1.1 request message-boundary adjudicator.

The adjudicator parses exactly one HTTP/1.1 request message from a raw
capture and decides a single, unambiguous message boundary.  It is strict
by design: anything two HTTP implementations could reasonably disagree on
(duplicate lengths, mixed framing, chunk extensions, undeclared trailers,
extra bytes after the message) is rejected with a stable error code and
the zero-based offset of the first offending byte in the decoded capture.

Verdict error codes
-------------------
EMPTY_MESSAGE          capture is empty
MESSAGE_TOO_LARGE      decoded capture exceeds 256 KiB
BAD_CRLF               bare LF where CRLF is required (header section)
INCOMPLETE_MESSAGE     header-section line is not CRLF-terminated before EOF
BAD_REQUEST_LINE       request line is not '<method> SP <target> SP HTTP/1.1'
BAD_METHOD             method is not a valid RFC 7230 token
BAD_TARGET             target is not ASCII origin-form
BAD_VERSION            HTTP version is not HTTP/1.1
BAD_HEADER             malformed header field (bad name/value, obs-fold, ...)
MISSING_HOST           no Host header field
DUPLICATE_HOST         more than one Host header field
AMBIGUOUS_FRAMING      CL+TE combined, repeated CL/TE, or TE not exactly 'chunked'
BAD_CONTENT_LENGTH     Content-Length is not a canonical decimal
TRUNCATED_BODY         fewer body bytes available than Content-Length
BAD_CHUNK              bad chunk size / extension / data / terminator
ILLEGAL_TRAILER        undeclared, forbidden or malformed trailer field
TRAILING_BYTES         extra bytes after the end of the message
"""

from __future__ import annotations

import hashlib

MAX_CAPTURE_BYTES = 256 * 1024  # 256 KiB

# RFC 7230 token characters, as a set of byte values.
_TCHAR = frozenset(
    b"!#$%&'*+-.^_`|~0123456789"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_HEXDIG = frozenset(b"0123456789abcdefABCDEF")

# Fields that may never appear in a trailer part: message framing
# (Content-Length, Transfer-Encoding, Trailer, TE) and routing /
# connection management (Host, Connection, Keep-Alive, Upgrade).
_FORBIDDEN_TRAILER_FIELDS = frozenset({
    b"content-length",
    b"transfer-encoding",
    b"trailer",
    b"te",
    b"host",
    b"connection",
    b"keep-alive",
    b"upgrade",
})


class AuditError(Exception):
    """Adjudication failure.

    ``code`` is a stable machine-readable error code and ``offset`` is the
    zero-based offset of the first offending byte in the decoded capture.
    """

    def __init__(self, code: str, offset: int, detail: str = "") -> None:
        super().__init__(f"{code} at byte {offset}: {detail}")
        self.code = code
        self.offset = offset
        self.detail = detail


def _is_token(raw: bytes) -> bool:
    return len(raw) > 0 and all(b in _TCHAR for b in raw)


def _is_canonical_decimal(raw: bytes) -> bool:
    """Canonical decimal: digits only, no leading zeros unless exactly '0'."""
    return (
        len(raw) > 0
        and all(0x30 <= b <= 0x39 for b in raw)
        and (len(raw) == 1 or raw[0] != 0x30)
    )


def _read_crlf_line(data: bytes, pos: int, *, incomplete_code: str,
                    bare_lf_code: str) -> tuple[bytes, int]:
    """Return the CRLF-terminated line starting at ``pos`` (without the
    CRLF) and the offset of the next line."""
    idx = data.find(b"\n", pos)
    if idx == -1:
        raise AuditError(incomplete_code, len(data),
                         "line is not CRLF-terminated")
    if idx == pos or data[idx - 1] != 0x0D:
        raise AuditError(bare_lf_code, idx, "bare LF line terminator")
    return data[pos:idx - 1], idx + 1


def _strip_ows(line: bytes, start: int, line_off: int) -> tuple[bytes, int]:
    """Strip leading/trailing optional whitespace (SP / HTAB)."""
    end = len(line)
    while start < end and line[start] in (0x20, 0x09):
        start += 1
    while end > start and line[end - 1] in (0x20, 0x09):
        end -= 1
    return line[start:end], line_off + start


def _parse_request_line(line: bytes) -> tuple[str, str]:
    parts = line.split(b" ")
    if len(parts) != 3 or b"" in parts:
        raise AuditError("BAD_REQUEST_LINE", 0,
                         "expected '<method> SP <origin-form> SP HTTP/1.1'")
    method, target, version = parts
    if not _is_token(method):
        raise AuditError("BAD_METHOD", 0, "method must be a non-empty token")
    target_off = len(method) + 1
    if not target.startswith(b"/"):
        raise AuditError("BAD_TARGET", target_off,
                         "target must be origin-form (start with '/')")
    for i, b in enumerate(target):
        if b < 0x21 or b > 0x7E:
            raise AuditError("BAD_TARGET", target_off + i,
                             "target must be visible ASCII")
    version_off = target_off + len(target) + 1
    if version != b"HTTP/1.1":
        raise AuditError("BAD_VERSION", version_off, "only HTTP/1.1 is accepted")
    return method.decode("ascii"), target.decode("ascii")


def _parse_header_line(line: bytes, line_off: int) -> tuple[bytes, bytes, bytes, int]:
    """Parse one header field line.

    Returns ``(lower_name, raw_name, value, line_offset)`` with the value
    stripped of optional whitespace.
    """
    if line[:1] in (b" ", b"\t"):
        raise AuditError("BAD_HEADER", line_off,
                         "obsolete folded headers are not accepted")
    colon = line.find(b":")
    if colon <= 0:
        raise AuditError("BAD_HEADER", line_off, "header field missing ':'")
    name = line[:colon]
    if not _is_token(name):
        raise AuditError("BAD_HEADER", line_off, "invalid header field name")
    value, value_off = _strip_ows(line, colon + 1, line_off)
    for i, b in enumerate(value):
        if not (b == 0x09 or 0x20 <= b <= 0x7E):
            raise AuditError("BAD_HEADER", value_off + i,
                             "header value must be printable ASCII")
    return name.lower(), name, value, line_off


def _declared_trailer_fields(headers: list) -> set[bytes]:
    """Collect the field names pre-declared by Trailer header fields."""
    declared: set[bytes] = set()
    for lname, _raw, value, off in headers:
        if lname != b"trailer":
            continue
        for item in value.split(b","):
            item = item.strip(b" \t")
            if not item:
                continue
            if not _is_token(item):
                raise AuditError("BAD_HEADER", off,
                                 "Trailer must list header field names")
            declared.add(item.lower())
    return declared


def _parse_trailer_line(line: bytes, line_off: int,
                        declared: set[bytes]) -> dict:
    if line[:1] in (b" ", b"\t"):
        raise AuditError("ILLEGAL_TRAILER", line_off,
                         "folded trailer fields are not accepted")
    colon = line.find(b":")
    if colon <= 0:
        raise AuditError("ILLEGAL_TRAILER", line_off, "trailer field missing ':'")
    name = line[:colon]
    lname = name.lower()
    if not _is_token(name):
        raise AuditError("ILLEGAL_TRAILER", line_off, "invalid trailer field name")
    if lname in _FORBIDDEN_TRAILER_FIELDS:
        raise AuditError("ILLEGAL_TRAILER", line_off,
                         "framing or routing fields are not allowed in a trailer")
    if lname not in declared:
        raise AuditError("ILLEGAL_TRAILER", line_off,
                         "trailer field was not declared by the Trailer header")
    value, value_off = _strip_ows(line, colon + 1, line_off)
    for i, b in enumerate(value):
        if not (b == 0x09 or 0x20 <= b <= 0x7E):
            raise AuditError("ILLEGAL_TRAILER", value_off + i,
                             "trailer value must be printable ASCII")
    return {"name": name.decode("ascii"), "value": value.decode("ascii")}


def _parse_chunked_body(data: bytes, pos: int,
                        declared: set[bytes]) -> tuple[bytes, list, int]:
    """Parse a chunked body.  Returns (decoded_body, trailers, end_offset)."""
    decoded = bytearray()
    trailers: list[dict] = []
    while True:
        line_off = pos
        size_line, pos = _read_crlf_line(
            data, pos, incomplete_code="BAD_CHUNK", bare_lf_code="BAD_CHUNK")
        if not size_line:
            raise AuditError("BAD_CHUNK", line_off, "empty chunk-size line")
        for i, b in enumerate(size_line):
            if b == 0x3B:  # ';'
                raise AuditError("BAD_CHUNK", line_off + i,
                                 "chunk extensions are not accepted")
            if b not in _HEXDIG:
                raise AuditError("BAD_CHUNK", line_off + i,
                                 "chunk size must be hexadecimal")
        size = int(size_line, 16)
        if size == 0:
            # Last chunk: optional trailer part, then a final empty line.
            while True:
                trailer_off = pos
                line, pos = _read_crlf_line(
                    data, pos, incomplete_code="BAD_CHUNK",
                    bare_lf_code="BAD_CHUNK")
                if line == b"":
                    break
                trailers.append(_parse_trailer_line(line, trailer_off, declared))
            return bytes(decoded), trailers, pos
        if len(data) - pos < size:
            raise AuditError("BAD_CHUNK", len(data), "chunk data is truncated")
        if data[pos + size:pos + size + 2] != b"\r\n":
            raise AuditError("BAD_CHUNK", pos + size,
                             "chunk data must be followed by CRLF")
        decoded += data[pos:pos + size]
        pos += size + 2


def audit(data: bytes) -> dict:
    """Adjudicate the message boundary of one raw HTTP/1.1 request.

    Returns the verdict dict on success, raises :class:`AuditError` with a
    stable code and first-error byte offset otherwise.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("capture must be bytes")
    data = bytes(data)
    if len(data) == 0:
        raise AuditError("EMPTY_MESSAGE", 0, "capture is empty")
    if len(data) > MAX_CAPTURE_BYTES:
        raise AuditError("MESSAGE_TOO_LARGE", MAX_CAPTURE_BYTES,
                         "capture exceeds 256 KiB")

    # --- request line --------------------------------------------------
    line, pos = _read_crlf_line(data, 0, incomplete_code="INCOMPLETE_MESSAGE",
                                bare_lf_code="BAD_CRLF")
    method, target = _parse_request_line(line)

    # --- header section --------------------------------------------------
    headers: list[tuple[bytes, bytes, bytes, int]] = []
    while True:
        line_off = pos
        line, pos = _read_crlf_line(data, pos,
                                    incomplete_code="INCOMPLETE_MESSAGE",
                                    bare_lf_code="BAD_CRLF")
        if line == b"":
            break
        headers.append(_parse_header_line(line, line_off))
    body_start = pos

    # --- Host: exactly one ------------------------------------------------
    hosts = [h for h in headers if h[0] == b"host"]
    if not hosts:
        raise AuditError("MISSING_HOST", body_start,
                         "exactly one Host header is required")
    if len(hosts) > 1:
        raise AuditError("DUPLICATE_HOST", hosts[1][3],
                         "only one Host header is allowed")
    if not hosts[0][2]:
        raise AuditError("BAD_HEADER", hosts[0][3],
                         "Host value must not be empty")
    host = hosts[0][2].decode("ascii")

    # --- framing ----------------------------------------------------------
    tes = [h for h in headers if h[0] == b"transfer-encoding"]
    cls = [h for h in headers if h[0] == b"content-length"]

    if tes and cls:
        raise AuditError("AMBIGUOUS_FRAMING", cls[0][3],
                         "Content-Length must not appear with Transfer-Encoding")
    if len(tes) > 1:
        raise AuditError("AMBIGUOUS_FRAMING", tes[1][3],
                         "multiple Transfer-Encoding header fields")
    if len(cls) > 1:
        raise AuditError("AMBIGUOUS_FRAMING", cls[1][3],
                         "multiple Content-Length header fields")

    framing = "none"
    content_length = 0
    if tes:
        if tes[0][2].lower() != b"chunked":
            raise AuditError("AMBIGUOUS_FRAMING", tes[0][3],
                             "Transfer-Encoding must be exactly 'chunked'")
        framing = "chunked"
    elif cls:
        cl_raw = cls[0][2]
        if not _is_canonical_decimal(cl_raw):
            raise AuditError(
                "BAD_CONTENT_LENGTH", cls[0][3],
                "Content-Length must be a single canonical decimal value")
        if len(cl_raw) > 6:  # > 999999 bytes can never fit in a 256 KiB capture
            raise AuditError("TRUNCATED_BODY", len(data),
                             "Content-Length exceeds the capture size limit")
        content_length = int(cl_raw)
        framing = "content-length"

    # --- body -------------------------------------------------------------
    body = b""
    trailers: list[dict] = []

    if framing == "content-length":
        available = len(data) - body_start
        if available < content_length:
            raise AuditError(
                "TRUNCATED_BODY", len(data),
                f"body shorter than Content-Length ({available} < {content_length})")
        if available > content_length:
            raise AuditError("TRAILING_BYTES", body_start + content_length,
                             "unexpected bytes after end of message")
        body = data[body_start:]
    elif framing == "chunked":
        declared = _declared_trailer_fields(headers)
        body, trailers, end = _parse_chunked_body(data, body_start, declared)
        if end != len(data):
            raise AuditError("TRAILING_BYTES", end,
                             "unexpected bytes after end of message")
    else:  # no framing headers -> no body
        if body_start != len(data):
            raise AuditError("TRAILING_BYTES", body_start,
                             "unexpected bytes after end of message")

    return {
        "method": method,
        "target": target,
        "host": host,
        "framing": framing,
        "bodyLength": len(body),
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "trailers": trailers,
    }
