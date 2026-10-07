"""Strict offline adjudicator for one captured HTTP/1.1 request message.

The input is exactly one captured request.  A successful verdict means the
capture has a unique message boundary: the parse position ends exactly at the
end of the data, and the request body length is unambiguous for every
implementation.

Only the subset required by the gateway policy is accepted:

* request line = method SP origin-form SP "HTTP/1.1", CRLF line endings
* exactly one ``Host`` header field
* zero or one *canonical* ``Content-Length`` (DIGIT only, no leading zeros),
  or a single ``Transfer-Encoding: chunked``, never both
* chunked coding without chunk extensions, with full chunks and a last chunk
* trailer fields declared up front by ``Trailer``, with no framing/routing
  fields, and no bytes after the terminating empty line

Errors carry a stable machine readable code plus the offset of the first byte
that makes the capture invalid (``len(data)`` for unexpected EOF, ``None``
when no single byte is at fault).
"""

from __future__ import annotations

import hashlib

#: Maximum size of a decoded capture.
MAX_CAPTURE = 256 * 1024

CR, LF = 0x0D, 0x0A
SP, HT = 0x20, 0x09
COLON, COMMA, SEMICOLON, QUESTION, PERCENT = 0x3A, 0x2C, 0x3B, 0x3F, 0x25

_DIGIT = set(range(0x30, 0x3A))
_HEXDIG = set(b"0123456789abcdefABCDEF")
_UNRESERVED = set(
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"0123456789-._~"
)
# RFC 3986 sub-delims.
_SUB_DELIMS = set(b"!$&'()*+,;=")
# pchar minus percent-encoding; percent is handled by a state check.
_PCHAR = _UNRESERVED | _SUB_DELIMS | {0x3A, 0x40}  # ":" and "@"

# RFC 7230 tchar: legal bytes in a method or a field name.
_TCHAR = (
    set(b"!#$%&'*+-.^_`|~")
    | _DIGIT
    | set(range(0x41, 0x5B))  # A-Z
    | set(range(0x61, 0x7B))  # a-z
)

#: Field names that may never appear as trailer fields: message framing,
#: connection control or request routing headers.
FORBIDDEN_TRAILERS = frozenset(
    [
        "host",  # routing
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",  # framing
    ]
)


class VerdictError(Exception):
    """A rejected capture.

    :param code: stable, machine readable error code
    :param offset: byte offset of the first offending byte, ``len(data)`` for
        truncation, or ``None`` when no individual byte is at fault
    """

    def __init__(self, code: str, offset: int | None):
        super().__init__(f"{code} at byte {offset}")
        self.code = code
        self.offset = offset


def _is_hex(b: int) -> bool:
    return b in _HEXDIG


def _hex_le(digits: bytes, limit: int) -> bool:
    """Return ``int(digits, 16) <= limit`` without building a huge integer."""
    if limit < 0:
        return False
    stripped = digits.lstrip(b"0") or b"0"
    target = format(limit, "x").encode()
    if len(stripped) != len(target):
        return len(stripped) < len(target)
    return stripped.lower() <= target


def _pchar_error(buf: bytes, i: int) -> int | None:
    """Validate one RFC 3986 pchar element starting at ``i``.

    Returns the relative offset of the bad byte, or ``None`` when valid.
    """
    b = buf[i]
    if b in _PCHAR:
        return None
    if b == PERCENT:
        if i + 2 < len(buf) and _is_hex(buf[i + 1]) and _is_hex(buf[i + 2]):
            return None
    return i


def _origin_form_error(target: bytes) -> int | None:
    """Validate an ASCII RFC 7230 origin-form (``absolute-path [ "?" query ]``)."""
    if not target or target[0] != 0x2F:  # must start with "/"
        return 0
    question = target.find(b"?")
    if question < 0:
        path, query = target, b""
    else:
        path, query = target[:question], target[question + 1:]

    i = 0
    while i < len(path):
        b = path[i]
        if b == 0x2F:
            i += 1
            continue
        bad = _pchar_error(path, i)
        if bad is not None:
            return bad
        i += 3 if path[i] == PERCENT else 1

    j = 0
    while j < len(query):
        b = query[j]
        if b == 0x2F or b == QUESTION:  # "/" and "?" are extra-allowed in query
            j += 1
            continue
        bad = _pchar_error(query, j)
        if bad is not None:
            return question + 1 + bad
        j += 3 if query[j] == PERCENT else 1
    return None


def _valid_host(value: bytes) -> bool:
    """Validate the contents of a Host header (uri-host [ ":" port ])."""
    if not value:
        return False
    if any(b < 0x21 or b > 0x7E for b in value):
        return False
    if value[0] == 0x5B:  # "[" IP-literal (IPv6 / IPvFuture)
        close = value.find(b"]")
        if close <= 1:
            return False
        inside = value[1:close]
        tail = value[close + 1:]
        if tail and not (
            tail[:1] == b":" and len(tail) > 1 and all(c in _DIGIT for c in tail[1:])
        ):
            return False
        allowed = _UNRESERVED | _SUB_DELIMS | {0x3A, 0x2E}  # ":" and "."
        return len(inside) > 0 and all(c in allowed for c in inside)
    if b"@" in value:  # userinfo has no place in Host
        return False
    host = value
    if value.count(b":") == 1:
        host, port = value.rsplit(b":", 1)
        if not port or any(c not in _DIGIT for c in port):
            return False
    elif value.count(b":") > 1:
        return False
    if not host:
        return False
    i = 0
    while i < len(host):
        b = host[i]
        # reg-name = *( unreserved / pct-encoded / sub-delims )
        if b in _UNRESERVED or b in _SUB_DELIMS:
            i += 1
            continue
        if b == PERCENT and _pchar_error(host, i) is None:
            i += 3
            continue
        return False
    return True


class _Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.n = len(data)
        self.pos = 0

    # -- line level -------------------------------------------------------

    def _read_line(self, eof_code: str) -> bytes:
        """Read one logical line terminated by CRLF.

        Bare CR or bare LF is rejected at the offending byte.  The returned
        slice excludes the CRLF; ``self.pos`` points just after it.
        """
        start = self.pos
        i = start
        while i < self.n:
            b = self.data[i]
            if b == LF:
                # LF must be the second half of a CRLF.
                if i == start or self.data[i - 1] != CR:
                    raise VerdictError("bad_line_ending", i)
                self.pos = i + 1
                return self.data[start : i - 1]
            if b == CR:
                if i + 1 >= self.n or self.data[i + 1] != LF:
                    raise VerdictError("bad_line_ending", i)
                self.pos = i + 2
                return self.data[start:i]
            i += 1
        raise VerdictError(eof_code, self.n)

    # -- field lines ------------------------------------------------------

    def _split_field(
        self,
        line: bytes,
        line_start: int,
        structural_code: str,
        bad_name_code: str,
    ) -> tuple[bytes, str, bytes, int, int]:
        colon = line.find(b":")
        if colon <= 0:
            raise VerdictError(structural_code, line_start)
        name = line[:colon]
        for off, b in enumerate(name):
            if b not in _TCHAR:
                raise VerdictError(bad_name_code, line_start + off)
        raw_value = line[colon + 1:]
        a, z = 0, len(raw_value)
        while a < z and raw_value[a] in (SP, HT):
            a += 1
        while z > a and raw_value[z - 1] in (SP, HT):
            z -= 1
        core = raw_value[a:z]
        value_abs = line_start + colon + 1
        for off, b in enumerate(core):
            # Field content is VCHAR / obs-text / HT; other controls rejected.
            if (b < 0x20 and b != HT) or b == 0x7F:
                raise VerdictError(structural_code, value_abs + a + off)
        return name.lower(), name.decode("ascii"), core, line_start, value_abs + a

    # -- request line -----------------------------------------------------

    def _parse_request_line(self) -> tuple[str, bytes]:
        line = self._read_line("incomplete_request_line")
        start = 0

        # method = 1*tchar, terminated by SP
        i = 0
        while i < len(line) and line[i] != SP:
            if line[i] not in _TCHAR:
                raise VerdictError("invalid_method", start + i)
            i += 1
        if i == 0:
            raise VerdictError("malformed_request_line", start)
        method = line[:i].decode("ascii")

        # single SP, then request-target up to the next single SP
        if i >= len(line):
            raise VerdictError("malformed_request_line", start + len(line))
        j = i + 1
        target_start = j
        while j < len(line) and line[j] != SP:
            j += 1
        if j >= len(line):
            raise VerdictError("malformed_request_line", start + len(line))
        target = line[target_start:j]
        bad = _origin_form_error(target)
        if bad is not None:
            raise VerdictError("invalid_request_target", target_start + bad)

        # single SP, then exactly HTTP/1.1
        k = j + 1
        rest = line[k:]
        if not rest or SP in rest:
            raise VerdictError("malformed_request_line", start + k)
        if rest != b"HTTP/1.1":
            raise VerdictError("invalid_http_version", start + k)
        return method, target

    # -- trailer declaration ---------------------------------------------

    def _parse_trailer_declaration(self, core: bytes, value_abs: int) -> list[bytes]:
        names: list[bytes] = []
        start = 0
        idx = 0
        while idx <= len(core):
            if idx == len(core) or core[idx] == COMMA:
                part = core[start:idx]
                a, z = 0, len(part)
                while a < z and part[a] in (SP, HT):
                    a += 1
                while z > a and part[z - 1] in (SP, HT):
                    z -= 1
                token = part[a:z]
                if not token:
                    raise VerdictError(
                        "invalid_trailer_declaration", value_abs + start + a
                    )
                for off, b in enumerate(token):
                    if b not in _TCHAR:
                        raise VerdictError(
                            "invalid_trailer_declaration",
                            value_abs + start + a + off,
                        )
                names.append(token.lower())
                start = idx + 1
            idx += 1
        return names

    # -- headers ----------------------------------------------------------

    def _parse_headers(self):
        host_value: bytes | None = None
        content_length: int | None = None
        transfer_encoding_seen = False
        declared_trailers: list[bytes] = []

        while True:
            line_start = self.pos
            line = self._read_line("incomplete_header_section")
            if not line:
                break  # empty line terminates the header section
            if line[0] in (SP, HT):
                # Obsolete line folding is a classic smuggling vector.
                raise VerdictError("obsolete_line_folding", line_start)

            name_l, _, core, name_off, value_off = self._split_field(
                line, line_start, "malformed_header", "invalid_header_name"
            )

            if name_l == b"host":
                if host_value is not None:
                    raise VerdictError("duplicate_host", name_off)
                if not _valid_host(core):
                    raise VerdictError("invalid_host", value_off)
                host_value = core
            elif name_l == b"content-length":
                if content_length is not None:
                    raise VerdictError("duplicate_content_length", name_off)
                if transfer_encoding_seen:
                    raise VerdictError("conflicting_framing", name_off)
                if not core or any(c not in _DIGIT for c in core):
                    raise VerdictError("invalid_content_length", value_off)
                if len(core) > 1 and core[0] == 0x30:  # no leading zeros
                    raise VerdictError("invalid_content_length", value_off)
                content_length = int(core)
            elif name_l == b"transfer-encoding":
                if transfer_encoding_seen:
                    raise VerdictError("invalid_transfer_encoding", name_off)
                if content_length is not None:
                    raise VerdictError("conflicting_framing", name_off)
                # The only accepted coding is a single, bare "chunked".
                if core.lower() != b"chunked" or COMMA in core:
                    raise VerdictError("invalid_transfer_encoding", value_off)
                transfer_encoding_seen = True
            elif name_l == b"trailer":
                declared_trailers.extend(
                    self._parse_trailer_declaration(core, value_off)
                )

        if host_value is None:
            # Absence has no offending byte; the caller reports offset null.
            raise VerdictError("missing_host", None)
        return host_value, content_length, transfer_encoding_seen, set(
            declared_trailers
        )

    # -- chunked body -----------------------------------------------------

    def _parse_chunked(self, declared: set[bytes]):
        body_parts: list[bytes] = []
        while True:
            line_start = self.pos
            line = self._read_line("incomplete_chunk")
            if not line or line[0] not in _HEXDIG:
                raise VerdictError("invalid_chunk_size", line_start)
            i = 0
            while i < len(line) and line[i] in _HEXDIG:
                i += 1
            size_digits = line[:i]
            if i < len(line):
                if line[i] == SEMICOLON:
                    raise VerdictError("chunk_extension_not_allowed", line_start + i)
                raise VerdictError("invalid_chunk_size", line_start + i)

            avail = self.n - self.pos
            # A non-final chunk needs size data bytes plus the trailing CRLF.
            if not _hex_le(size_digits, avail - 2):
                raise VerdictError("incomplete_chunk", self.n)
            size = int(size_digits, 16)
            if size == 0:
                # Last chunk: no chunk-data, straight into the trailer part.
                trailers = self._parse_trailer_section(declared)
                return b"".join(body_parts), trailers
            data_start = self.pos
            data_end = data_start + size
            terminator = self.data[data_end : data_end + 2]
            if terminator != b"\r\n":
                bad = data_end
                if terminator[:1] == b"\r":
                    bad = data_end + 1
                raise VerdictError("bad_chunk_terminator", bad)
            body_parts.append(self.data[data_start:data_end])
            self.pos = data_end + 2

    def _parse_trailer_section(self, declared: set[bytes]):
        trailers: list[dict[str, str]] = []
        while True:
            line_start = self.pos
            line = self._read_line("incomplete_trailer")
            if not line:
                break  # terminating empty line
            if line[0] in (SP, HT):
                raise VerdictError("obsolete_line_folding", line_start)
            name_l, raw_name, core, name_off, _ = self._split_field(
                line, line_start, "malformed_trailer", "malformed_trailer"
            )
            if name_l.decode("ascii") in FORBIDDEN_TRAILERS:
                raise VerdictError("forbidden_trailer", name_off)
            if name_l not in declared:
                raise VerdictError("undeclared_trailer", name_off)
            trailers.append({"name": raw_name, "value": core.decode("latin-1")})
        if self.pos != self.n:
            raise VerdictError("trailing_bytes", self.pos)
        return trailers

    # -- entry point ------------------------------------------------------

    def parse(self) -> dict:
        method, target = self._parse_request_line()
        host, content_length, chunked, declared_trailers = self._parse_headers()
        body_start = self.pos

        if chunked:
            body, trailers = self._parse_chunked(declared_trailers)
            framing = "chunked"
        elif content_length is not None:
            end = body_start + content_length
            if end > self.n:
                raise VerdictError("content_length_mismatch", self.n)
            body = self.data[body_start:end]
            if end != self.n:
                raise VerdictError("trailing_bytes", end)
            trailers = []
            framing = "content-length"
        else:
            if body_start != self.n:
                raise VerdictError("trailing_bytes", body_start)
            body = b""
            trailers = []
            framing = "none"

        return {
            "ok": True,
            "method": method,
            "target": target.decode("ascii"),
            "host": host.decode("ascii"),
            "framing": framing,
            "bodyLength": len(body),
            "bodySha256": hashlib.sha256(body).hexdigest(),
            "trailers": trailers,
        }


def adjudicate(data: bytes) -> dict:
    """Adjudicate one captured HTTP/1.1 request message.

    :raises VerdictError: on any policy violation
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("capture must be bytes")
    if len(data) > MAX_CAPTURE:
        raise VerdictError("payload_too_large", None)
    if len(data) == 0:
        raise VerdictError("empty_message", 0)
    return _Parser(bytes(data)).parse()
