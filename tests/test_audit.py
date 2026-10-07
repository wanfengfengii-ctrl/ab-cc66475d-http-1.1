"""Behavioural tests for the HTTP/1.1 offline adjudicator."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest

from app.parser import VerdictError, adjudicate


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def fixed_request(
    body: bytes = b"",
    host: bytes = b"example.com",
    extra_headers: bytes = b"",
    method: bytes = b"POST",
    target: bytes = b"/api/http1/audit",
) -> bytes:
    head = method + b" " + target + b" HTTP/1.1\r\nHost: " + host + b"\r\n"
    if extra_headers:
        head += extra_headers
    if body:
        head += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    return head + b"\r\n" + body


def chunked(
    chunks: list[bytes],
    host: bytes = b"example.com",
    trailers: bytes = b"",
    declared: bytes = b"",
    extra_head: bytes = b"",
) -> bytes:
    msg = b"POST /x HTTP/1.1\r\nHost: " + host + b"\r\nTransfer-Encoding: chunked\r\n"
    if declared:
        msg += b"Trailer: " + declared + b"\r\n"
    msg += extra_head + b"\r\n"
    for chunk in chunks:
        msg += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
    msg += b"0\r\n"
    msg += trailers
    msg += b"\r\n"
    return msg


class HappyPathTests(unittest.TestCase):
    def test_no_body(self):
        data = fixed_request()
        v = adjudicate(data)
        self.assertTrue(v["ok"])
        self.assertEqual(v["method"], "POST")
        self.assertEqual(v["target"], "/api/http1/audit")
        self.assertEqual(v["host"], "example.com")
        self.assertEqual(v["framing"], "none")
        self.assertEqual(v["bodyLength"], 0)
        self.assertEqual(v["bodySha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(v["trailers"], [])

    def test_explicit_zero_content_length(self):
        v = adjudicate(fixed_request(b"", extra_headers=b"Content-Length: 0\r\n"))
        self.assertEqual(v["framing"], "content-length")
        self.assertEqual(v["bodyLength"], 0)

    def test_fixed_body_matches_length_and_hash(self):
        body = b'{"hello": "\xe4\xb8\x96\xe7\x95\x8c"}'
        v = adjudicate(fixed_request(body))
        self.assertEqual(v["framing"], "content-length")
        self.assertEqual(v["bodyLength"], len(body))
        self.assertEqual(v["bodySha256"], hashlib.sha256(body).hexdigest())

    def test_chunked_basic(self):
        v = adjudicate(chunked([b"hel", b"lo"]))
        self.assertEqual(v["framing"], "chunked")
        self.assertEqual(v["bodyLength"], 5)
        self.assertEqual(v["bodySha256"], hashlib.sha256(b"hello").hexdigest())

    def test_chunked_empty_body(self):
        v = adjudicate(chunked([]))
        self.assertEqual(v["framing"], "chunked")
        self.assertEqual(v["bodyLength"], 0)

    def test_chunked_with_declared_trailers_preserves_arrival_order(self):
        msg = chunked(
            [b"abc"],
            declared=b"X-One, X-Two",
            trailers=b"X-One: 1\r\nX-Two: two\r\n",
        )
        v = adjudicate(msg)
        self.assertEqual(
            v["trailers"],
            [{"name": "X-One", "value": "1"}, {"name": "X-Two", "value": "two"}],
        )

    def test_origin_form_query_and_pct_encoding(self):
        v = adjudicate(fixed_request(target=b"/a/b%20c?x=1&y=%7e&z=/q"))
        self.assertEqual(v["target"], "/a/b%20c?x=1&y=%7e&z=/q")

    def test_host_with_port_ipv6(self):
        v = adjudicate(fixed_request(host=b"[2001:db8::1]:8443"))
        self.assertEqual(v["host"], "[2001:db8::1]:8443")

    def test_legal_token_methods(self):
        for method in (b"GET", b"POST", b"MKCOL", b"C.D-E_F"):
            v = adjudicate(fixed_request(method=method))
            self.assertEqual(v["method"], method.decode())

    def test_header_whitespace_is_trimmed_in_values(self):
        msg = (
            b"POST /x HTTP/1.1\r\nHost: h\r\n"
            b"Content-Length:\t 5  \t\r\n\r\nhello"
        )
        v = adjudicate(msg)
        self.assertEqual(v["bodyLength"], 5)


class LineEndingTests(unittest.TestCase):
    def test_bare_lf_request_line(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.1\nHost: x\r\n\r\n")
        self.assertEqual(ctx.exception.code, "bad_line_ending")
        self.assertEqual(ctx.exception.offset, 15)

    def test_bare_cr_in_header(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.1\r\nHost: x\rX\r\n\r\n")
        self.assertEqual(ctx.exception.code, "bad_line_ending")
        self.assertEqual(ctx.exception.offset, 24)

    def test_obsolete_fold_rejected(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.1\r\nX: a\r\n b\r\nHost: h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "obsolete_line_folding")
        self.assertEqual(ctx.exception.offset, 23)


class FramingAmbiguityTests(unittest.TestCase):
    def test_duplicate_content_length_same_value(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n"
            b"content-length: 0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "duplicate_content_length")
        self.assertEqual(ctx.exception.offset, msg.lower().find(b"content-length", 30))

    def test_noncanonical_content_length(self):
        msg = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 007\r\n\r\nabcdefg"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_content_length")
        self.assertEqual(msg[ctx.exception.offset : ctx.exception.offset + 3], b"007")

    def test_content_length_sp_inside(self):
        msg = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1 0\r\n\r\n"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_content_length")

    def test_content_length_plus_transfer_encoding_cl_first(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "conflicting_framing")

    def test_content_length_plus_transfer_encoding_te_first(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Length: 5\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "conflicting_framing")

    def test_transfer_encoding_identity_rejected(self):
        msg = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity\r\n\r\n"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_transfer_encoding")

    def test_transfer_encoding_chunked_list_rejected(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\n"
            b"Transfer-Encoding: gzip, chunked\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_transfer_encoding")

    def test_duplicate_transfer_encoding(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_transfer_encoding")

    def test_body_shorter_than_content_length(self):
        msg = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\nabc"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "content_length_mismatch")
        self.assertEqual(ctx.exception.offset, len(msg))

    def test_trailing_bytes_after_content_length_body(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhelloX"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "trailing_bytes")
        self.assertEqual(ctx.exception.offset, len(msg) - 1)

    def test_trailing_bytes_without_framing(self):
        msg = fixed_request() + b"X"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "trailing_bytes")
        self.assertEqual(ctx.exception.offset, len(msg) - 1)


class RequestLineTests(unittest.TestCase):
    def test_bad_method_token(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST\t/ HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "invalid_method")
        self.assertEqual(ctx.exception.offset, 4)

    def test_absolute_form_target_rejected(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST http://evil/x HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "invalid_request_target")
        self.assertEqual(ctx.exception.offset, 5)

    def test_target_with_space(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST /a b HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "malformed_request_line")

    def test_bad_pct_encoding(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST /%zz HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "invalid_request_target")

    def test_wrong_version(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.0\r\nHost: h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "invalid_http_version")

    def test_missing_host(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.1\r\nX: 1\r\n\r\n")
        self.assertEqual(ctx.exception.code, "missing_host")
        self.assertIsNone(ctx.exception.offset)

    def test_duplicate_host(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(
                b"POST / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"
            )
        self.assertEqual(ctx.exception.code, "duplicate_host")

    def test_invalid_host(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.1\r\nHost: user@h\r\n\r\n")
        self.assertEqual(ctx.exception.code, "invalid_host")

    def test_truncated_request_line(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"POST / HTTP/1.1")
        self.assertEqual(ctx.exception.code, "incomplete_request_line")
        self.assertEqual(ctx.exception.offset, 15)


class ChunkTests(unittest.TestCase):
    def test_chunk_extension_rejected_at_semicolon(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5;name=val\r\nhello\r\n0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "chunk_extension_not_allowed")
        self.assertEqual(msg[ctx.exception.offset : ctx.exception.offset + 1], b";")

    def test_bad_hex_size(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5z\r\nhello\r\n0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_chunk_size")
        self.assertEqual(msg[ctx.exception.offset : ctx.exception.offset + 1], b"z")

    def test_truncated_chunk_data(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhel"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "incomplete_chunk")
        self.assertEqual(ctx.exception.offset, len(msg))

    def test_missing_crlf_after_chunk_data(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhelloXX0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "bad_chunk_terminator")
        self.assertEqual(ctx.exception.offset, msg.find(b"XX"))

    def test_bare_lf_after_chunk_data(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\n0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "bad_chunk_terminator")
        self.assertEqual(msg[ctx.exception.offset : ctx.exception.offset + 1], b"\n")

    def test_missing_terminating_last_chunk(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "incomplete_chunk")

    def test_bytes_after_message_rejected(self):
        msg = chunked([b"hi"]) + b"X"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "trailing_bytes")
        self.assertEqual(ctx.exception.offset, len(msg) - 1)

    def test_declared_size_exceeds_capture_is_truncation_not_smuggle(self):
        # A gigantic declared chunk in a small capture must be reported as
        # truncation rather than parsed as zero chunks.
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"ffffffffffffffffff\r\nabc"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "incomplete_chunk")
        self.assertEqual(ctx.exception.offset, len(msg))


class TrailerTests(unittest.TestCase):
    def test_undeclared_trailer(self):
        msg = chunked([b"a"], trailers=b"X-Undeclared: 1\r\n")
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "undeclared_trailer")

    def test_forbidden_framing_trailer(self):
        msg = chunked([b"a"], declared=b"Content-Length",
                      trailers=b"Content-Length: 5\r\n")
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "forbidden_trailer")

    def test_forbidden_routing_trailer(self):
        msg = chunked([b"a"], declared=b"Host", trailers=b"Host: evil\r\n")
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "forbidden_trailer")

    def test_forbidden_transfer_encoding_trailer(self):
        msg = chunked(
            [b"a"], declared=b"Transfer-Encoding",
            trailers=b"Transfer-Encoding: chunked\r\n",
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "forbidden_trailer")

    def test_empty_trailer_declaration_element(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(chunked([b"a"], declared=b"X-A, , X-B"))
        self.assertEqual(ctx.exception.code, "invalid_trailer_declaration")

    def test_declared_but_absent_trailer_is_fine(self):
        v = adjudicate(chunked([b"a"], declared=b"X-A"))
        self.assertEqual(v["trailers"], [])

    def test_partial_declaration_rejected(self):
        msg = chunked(
            [b"a"], declared=b"X-One",
            trailers=b"X-One: 1\r\nX-Two: 2\r\n",
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "undeclared_trailer")


class SmugglingRegressionTests(unittest.TestCase):
    """Representative desync payloads that must never adjudicate as valid."""

    def test_space_before_colon_is_not_content_length(self):
        msg = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length : 5\r\n\r\nhello"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_header_name")

    def test_non_decimal_content_lengths(self):
        for value in (b"0x5", b"+5", b"5.0"):
            with self.subTest(value=value):
                msg = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: "
                msg += value + b"\r\n\r\n"
                with self.assertRaises(VerdictError) as ctx:
                    adjudicate(msg)
                self.assertEqual(ctx.exception.code, "invalid_content_length")

    def test_classic_cl_smuggle_payload(self):
        msg = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n0\r\n\r\nX"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "trailing_bytes")

    def test_classic_te_smuggle_payload(self):
        # GET-then-smuggled-line style: chunked parse sees non-hex data.
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"GET /admin HTTP/1.1\r\n\r\n0\r\n\r\n"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_chunk_size")

    def test_uppercase_hex_size_is_accepted(self):
        v = adjudicate(
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"A\r\n0123456789\r\n0\r\n\r\n"
        )
        self.assertEqual(v["bodyLength"], 10)

    def test_case_insensitive_te_value(self):
        v = adjudicate(
            b"POST / HTTP/1.1\r\nHost: h\r\n"
            b"Transfer-Encoding: ChUnKeD\r\n\r\n0\r\n\r\n"
        )
        self.assertEqual(v["framing"], "chunked")

    def test_http_response_disguise_rejected(self):
        msg = b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\n"
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "invalid_method")

    def test_double_zero_size_is_truncation(self):
        msg = (
            b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"ffffffffffffffffff\r\nabc"
        )
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(msg)
        self.assertEqual(ctx.exception.code, "incomplete_chunk")
        self.assertEqual(ctx.exception.offset, len(msg))


class EnvelopeTests(unittest.TestCase):
    def test_size_limit(self):
        big = b"x" * (256 * 1024 + 1)
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(big)
        self.assertEqual(ctx.exception.code, "payload_too_large")

    def test_empty(self):
        with self.assertRaises(VerdictError) as ctx:
            adjudicate(b"")
        self.assertEqual(ctx.exception.code, "empty_message")
        self.assertEqual(ctx.exception.offset, 0)

    def test_json_envelope_directly(self):
        from app.server import audit_payload

        status, payload = audit_payload(
            json.dumps({"captureBase64": b64(fixed_request())}).encode()
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_json_envelope_bad_base64(self):
        from app.server import audit_payload

        status, payload = audit_payload(
            json.dumps({"captureBase64": "@@not-base64@@"}).encode()
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_base64")

    def test_json_envelope_bad_message_is_422(self):
        from app.server import audit_payload

        status, payload = audit_payload(
            json.dumps(
                {"captureBase64": b64(fixed_request() + b"X")}
            ).encode()
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"], "trailing_bytes")
        self.assertIsInstance(payload["offset"], int)


if __name__ == "__main__":
    unittest.main(verbosity=2)
