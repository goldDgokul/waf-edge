"""0B.1: canonical request model.

Plan v7.5 0B.1: "Normalise path/query plus selected headers/cookies and
supported request bodies before matching. Preserve raw and canonical forms
separately, with strict size/content-type/privacy limits."

These tests pin the contract of src/canonical.py:
  - raw forms are preserved byte-for-byte alongside canonical (decoded) ones;
  - percent-encoding is decoded for matching, with a bounded decode depth and
    explicit flags for double-encoding / malformed escapes / null bytes;
  + only selected headers and cookie NAMES enter the canonical model, and
    credential values (Authorization, Cookie values) never do (privacy);
  - request bodies are only carried when the content type is supported and
    the size is within limit; everything else is omitted with a flag.
"""

import pytest

from src.canonical import (
    MAX_BODY_BYTES,
    MAX_URL_BYTES,
    canonicalize,
    split_url,
)


class TestUrlSplitting:
    def test_url_with_query_is_split_into_raw_path_and_raw_query(self):
        assert split_url("/api/search?q=union+select") == ("/api/search", "q=union+select")

    def test_url_without_query_has_empty_query(self):
        assert split_url("/") == ("/", "")

    def test_raw_path_is_preserved_exactly(self):
        # NOT unescaped: the raw form keeps the literal %2F bytes.
        assert split_url("/api/%2e%2e/secret?x=%2f")[0] == "/api/%2e%2e/secret"


class TestCanonicalDecoding:
    def test_percent_encoded_javascript_is_decoded_for_matching(self):
        c = canonicalize(url="/?q=%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)")
        assert "javascript:alert(1)" in c.canonical_query

    def test_raw_query_preserved_next_to_canonical(self):
        c = canonicalize(url="/?q=%3Cscript%3E")
        assert c.raw_query == "q=%3Cscript%3E"
        assert "<script>" in c.canonical_query

    def test_double_encoding_is_decoded_with_depth_flag(self):
        c = canonicalize(url="/?q=%253Cscript%253E")
        assert "<script>" in c.canonical_query
        assert "double-encoded" in c.decode_flags
        assert c.decode_depth >= 2

    def test_decode_depth_is_bounded(self):
        # 10 nested encodings: the model must stop at its bound, not recurse forever.
        payload = "<script>"
        for _ in range(10):
            from urllib.parse import quote

            payload = quote(payload)
        c = canonicalize(url=f"/?q={payload}")
        assert c.decode_depth <= 3

    def test_malformed_percent_escape_is_flagged_not_crashed(self):
        c = canonicalize(url="/?q=100%zz%2")
        assert "malformed-escape" in c.decode_flags

    def test_null_byte_in_decoded_form_is_flagged(self):
        c = canonicalize(url="/?q=%00etc")
        assert "null-byte" in c.decode_flags

    def test_plus_in_query_means_space(self):
        c = canonicalize(url="/?q=1+OR+1%3D1")
        assert "or 1=1" in c.canonical_query.lower()


class TestHeaderAndCookieSelection:
    def test_selected_headers_are_carried_lowercase(self):
        c = canonicalize(
            url="/",
            headers={"User-Agent": "sqlmap/1.0", "Content-Type": "application/json"},
        )
        assert c.headers["user-agent"] == "sqlmap/1.0"
        assert c.headers["content-type"] == "application/json"

    def test_authorization_value_never_enters_the_model(self):
        c = canonicalize(
            url="/", headers={"Authorization": "Bearer super-secret-token"}
        )
        assert "super-secret-token" not in str(c.headers)
        assert "super-secret-token" not in c.inspection_text()

    def test_cookie_values_never_enter_the_model_names_do(self):
        c = canonicalize(
            url="/", headers={"Cookie": "session=secret-value-123; theme=dark"}
        )
        assert "secret-value-123" not in c.inspection_text()
        assert "session" in c.cookie_names
        assert "theme" in c.cookie_names

    def test_inspection_text_contains_raw_and_canonical(self):
        c = canonicalize(url="/api/search?q=%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)")
        text = c.inspection_text()
        assert "javascript:alert(1)" in text  # canonical
        assert "%6A%61%76" in text  # raw


class TestBodyPolicy:
    def test_form_body_is_carried_and_decoded(self):
        c = canonicalize(
            url="/api/login",
            body="username=admin'--&password=x",
            content_type="application/x-www-form-urlencoded",
        )
        assert c.body_included is True
        assert "admin'--" in c.canonical_body

    def test_json_body_is_carried(self):
        c = canonicalize(
            url="/api/login", body='{"user":"a"}', content_type="application/json"
        )
        assert c.body_included is True
        assert '"user"' in c.canonical_body

    def test_binary_content_type_is_omitted_with_flag(self):
        c = canonicalize(
            url="/upload", body=b"\x00\x01\x02", content_type="application/octet-stream"
        )
        assert c.body_included is False
        assert "unsupported-content-type" in c.body_flags

    def test_oversized_body_is_omitted_with_flag(self):
        c = canonicalize(
            url="/upload",
            body="x" * (MAX_BODY_BYTES + 1),
            content_type="text/plain",
        )
        assert c.body_included is False
        assert "body-too-large" in c.body_flags

    def test_oversized_url_is_flagged(self):
        c = canonicalize(url="/" + "a" * (MAX_URL_BYTES + 1))
        assert "url-too-large" in c.decode_flags


class TestCollectorWiring:
    """The collector's pattern checks must run over the canonical text, so the
    measured percent-encoded bypass classes are detected by the analysis path."""

    def _request(self, url, headers=None, body=None):
        from datetime import datetime

        from src.traffic_collector import HttpRequest

        return HttpRequest(
            timestamp=datetime.now(),
            method="GET" if body is None else "POST",
            url=url,
            headers=headers or {},
            body=body,
            source_ip="1.2.3.4",
            user_agent=(headers or {}).get("User-Agent", ""),
            content_length=len(body or ""),
        )

    def test_encoded_xss_detected_through_canonical_path(self):
        req = self._request(url="/api/search?q=%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)")
        assert req.to_dict()["contains_xss_patterns"] is True

    def test_clean_request_not_flagged(self):
        req = self._request(url="/api/search?q=the+union+of+two+sets")
        d = req.to_dict()
        assert d["contains_xss_patterns"] is False
        assert d["contains_sql_patterns"] is False

    def test_dict_keeps_raw_url(self):
        req = self._request(url="/api/search?q=%3Cscript%3E")
        d = req.to_dict()
        assert d["url"] == "/api/search?q=%3Cscript%3E"
        assert d["canonical_query"].find("<script>") >= 0

    def test_body_sqli_detected_through_canonical_body(self):
        req = self._request(
            url="/api/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=1'+OR+1%3D1&password=x",
        )
        assert req.to_dict()["contains_sql_patterns"] is True

    def test_header_xss_detected_via_selected_headers(self):
        req = self._request(
            url="/api/users", headers={"User-Agent": "<script>alert(1)</script>"}
        )
        assert req.to_dict()["contains_xss_patterns"] is True
