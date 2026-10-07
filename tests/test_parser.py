import hashlib
import unittest

from app.parser import MAX_CAPTURE_BYTES, AuditError, audit

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class OkCases(unittest.TestCase):
    def test_get_no_body(self):
        doc = audit(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(doc["method"], "GET")
        self.assertEqual(doc["target"], "/")
        self.assertEqual(doc["host"], "example.com")
        self.assertEqual(doc["framing"], "none")
        self.assertEqual(doc["bodyLength"], 0)
        self.assertEqual(doc["bodySha256"], EMPTY_SHA256)
        self.assertEqual(doc["trailers"], [])

    def test_content_length_body(self):
        doc = audit(b"POST /submit?a=1 HTTP/1.1\r\nHost: h\r\n"
                    b"Content-Length: 5\r\n\r\nhello")
        self.assertEqual(doc["framing"], "content-length")
        self.assertEqual(doc["bodyLength"], 5)
        self.assertEqual(doc["bodySha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(doc["target"], "/submit?a=1")

    def test_content_length_zero(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(doc["framing"], "content-length")
        self.assertEqual(doc["bodyLength"], 0)
        self.assertEqual(doc["bodySha256"], EMPTY_SHA256)

    def test_content_length_with_ows(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length:  5 \r\n\r\nhello")
        self.assertEqual(doc["bodyLength"], 5)

    def test_chunked(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
        self.assertEqual(doc["framing"], "chunked")
        self.assertEqual(doc["bodyLength"], 9)
        self.assertEqual(doc["bodySha256"], hashlib.sha256(b"Wikipedia").hexdigest())

    def test_chunked_te_case_insensitive(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: ChUnKeD\r\n\r\n"
                    b"0\r\n\r\n")
        self.assertEqual(doc["framing"], "chunked")

    def test_chunk_sizes_hex_and_leading_zeros(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"000A\r\n0123456789\r\n000\r\n\r\n")
        self.assertEqual(doc["bodyLength"], 10)
        self.assertEqual(doc["bodySha256"], hashlib.sha256(b"0123456789").hexdigest())

    def test_trailers_declared_and_ordered(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nTrailer: X-B, X-A\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n0\r\n"
                    b"X-B: 1\r\nX-A: 2\r\nX-B: 3\r\n\r\n")
        self.assertEqual(doc["trailers"], [
            {"name": "X-B", "value": "1"},
            {"name": "X-A", "value": "2"},
            {"name": "X-B", "value": "3"},
        ])

    def test_trailer_declaration_case_insensitive(self):
        doc = audit(b"POST / HTTP/1.1\r\nHost: h\r\nTrailer: x-sum\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n0\r\nX-Sum: 9\r\n\r\n")
        self.assertEqual(doc["trailers"], [{"name": "X-Sum", "value": "9"}])

    def test_method_token_and_target_passthrough(self):
        doc = audit(b"M-SEARCH /a%20b?x=1&y=2 HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual(doc["method"], "M-SEARCH")
        self.assertEqual(doc["target"], "/a%20b?x=1&y=2")

    def test_max_size_capture_accepted(self):
        body = b"x" * (MAX_CAPTURE_BYTES - len(b"POST / HTTP/1.1\r\nHost: h\r\n"
                                              b"Content-Length: 262107\r\n\r\n"))
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.assertEqual(len(raw), MAX_CAPTURE_BYTES)
        self.assertEqual(audit(raw)["bodyLength"], len(body))


class ErrorCases(unittest.TestCase):
    def expect(self, raw, code, offset=None):
        with self.assertRaises(AuditError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, code)
        if offset is not None:
            self.assertEqual(ctx.exception.offset, offset)

    def test_empty(self):
        self.expect(b"", "EMPTY_MESSAGE", 0)

    def test_too_large(self):
        self.expect(b"A" * (MAX_CAPTURE_BYTES + 1),
                    "MESSAGE_TOO_LARGE", MAX_CAPTURE_BYTES)

    def test_bare_lf(self):
        raw = b"GET / HTTP/1.1\nHost: h\r\n\r\n"
        self.expect(raw, "BAD_CRLF", raw.index(b"\n"))

    def test_unterminated_header_section(self):
        raw = b"GET / HTTP/1.1\r\nHost: h"
        self.expect(raw, "INCOMPLETE_MESSAGE", len(raw))

    def test_bad_request_line(self):
        self.expect(b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n", "BAD_REQUEST_LINE", 0)

    def test_bad_method(self):
        self.expect(b"G@T / HTTP/1.1\r\nHost: h\r\n\r\n", "BAD_METHOD", 0)

    def test_absolute_form_target(self):
        self.expect(b"GET http://e/ HTTP/1.1\r\nHost: h\r\n\r\n", "BAD_TARGET", 4)

    def test_asterisk_target(self):
        self.expect(b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n", "BAD_TARGET", 8)

    def test_non_ascii_target(self):
        raw = "GET /café HTTP/1.1\r\nHost: h\r\n\r\n".encode("utf-8")
        self.expect(raw, "BAD_TARGET", raw.index("é".encode("utf-8")))

    def test_bad_version(self):
        self.expect(b"GET / HTTP/1.0\r\nHost: h\r\n\r\n", "BAD_VERSION", 6)

    def test_missing_host(self):
        self.expect(b"GET / HTTP/1.1\r\n\r\n", "MISSING_HOST")

    def test_duplicate_host(self):
        raw = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"
        self.expect(raw, "DUPLICATE_HOST", raw.index(b"Host: b"))

    def test_empty_host_value(self):
        self.expect(b"GET / HTTP/1.1\r\nHost:\r\n\r\n", "BAD_HEADER")

    def test_header_without_colon(self):
        self.expect(b"GET / HTTP/1.1\r\nHost: h\r\nBroken\r\n\r\n", "BAD_HEADER")

    def test_obs_fold_rejected(self):
        self.expect(b"GET / HTTP/1.1\r\nHost: h\r\nX: 1\r\n folded\r\n\r\n",
                    "BAD_HEADER")

    def test_space_before_colon(self):
        self.expect(b"GET / HTTP/1.1\r\nHost : h\r\n\r\n", "BAD_HEADER")

    def test_cl_and_te(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.expect(raw, "AMBIGUOUS_FRAMING", raw.index(b"Content-Length"))

    def test_duplicate_content_length_same_value(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n"
               b"Content-Length: 3\r\n\r\nabc")
        self.expect(raw, "AMBIGUOUS_FRAMING", raw.rindex(b"Content-Length"))

    def test_duplicate_content_length_different_value(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n"
               b"Content-Length: 5\r\n\r\nabcdef")
        self.expect(raw, "AMBIGUOUS_FRAMING", raw.rindex(b"Content-Length"))

    def test_noncanonical_content_length(self):
        for value in (b"05", b"+5", b"5x", b"", b"00", b"0x5"):
            raw = (b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: " + value
                   + b"\r\n\r\n")
            self.expect(raw, "BAD_CONTENT_LENGTH")

    def test_te_not_chunked(self):
        self.expect(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
                    "AMBIGUOUS_FRAMING")

    def test_te_chunked_in_list(self):
        self.expect(b"POST / HTTP/1.1\r\nHost: h\r\n"
                    b"Transfer-Encoding: chunked, gzip\r\n\r\n",
                    "AMBIGUOUS_FRAMING")

    def test_multiple_te(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.expect(raw, "AMBIGUOUS_FRAMING", raw.rindex(b"Transfer-Encoding"))

    def test_trailing_bytes_no_framing(self):
        raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\nXYZ"
        self.expect(raw, "TRAILING_BYTES", raw.index(b"X"))

    def test_trailing_bytes_after_cl(self):
        raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nabc"
        self.expect(raw, "TRAILING_BYTES", raw.index(b"c"))

    def test_truncated_body(self):
        raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc"
        self.expect(raw, "TRUNCATED_BODY", len(raw))

    def test_huge_content_length(self):
        raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999\r\n\r\nabc"
        self.expect(raw, "TRUNCATED_BODY", len(raw))

    def test_trailing_bytes_after_chunked(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"0\r\n\r\nZ")
        self.expect(raw, "TRAILING_BYTES", raw.index(b"Z"))

    def test_chunk_extension(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"4;foo=bar\r\nWiki\r\n0\r\n\r\n")
        self.expect(raw, "BAD_CHUNK", raw.index(b";"))

    def test_chunk_bad_hex(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"Z4\r\nWiki\r\n0\r\n\r\n")
        self.expect(raw, "BAD_CHUNK", raw.index(b"Z4"))

    def test_chunk_missing_crlf_after_data(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"2\r\nWiXX0\r\n\r\n")
        self.expect(raw, "BAD_CHUNK", raw.index(b"XX"))

    def test_chunk_truncated_data(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"8\r\nWi")
        self.expect(raw, "BAD_CHUNK", len(raw))

    def test_chunk_missing_final_crlf(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"0\r\n")
        self.expect(raw, "BAD_CHUNK", len(raw))

    def test_undeclared_trailer(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"0\r\nX-Sum: 1\r\n\r\n")
        self.expect(raw, "ILLEGAL_TRAILER", raw.index(b"X-Sum"))

    def test_forbidden_trailer_even_when_declared(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTrailer: Content-Length\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 3\r\n\r\n")
        self.expect(raw, "ILLEGAL_TRAILER", raw.rindex(b"Content-Length"))

    def test_host_in_trailer(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTrailer: Host\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n0\r\nHost: evil\r\n\r\n")
        self.expect(raw, "ILLEGAL_TRAILER", raw.rindex(b"Host:"))

    def test_transfer_encoding_in_trailer(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nTrailer: Transfer-Encoding\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n0\r\nTransfer-Encoding: x\r\n\r\n")
        self.expect(raw, "ILLEGAL_TRAILER", raw.rindex(b"Transfer-Encoding: x"))


if __name__ == "__main__":
    unittest.main()
