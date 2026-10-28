"""0B.1: canonical request model.

Plan v7.5 0B.1: "Normalise path/query plus selected headers/cookies and
supported request bodies before matching. Preserve raw and canonical forms
separately, with strict size/content-type/privacy limits."

Design:

- RAW AND CANONICAL ARE KEPT SEPARATELY. The raw URL/query/body bytes are
  preserved byte-for-byte; the canonical forms are bounded-depth percent
  decodings used only for MATCHING. Nothing in this module mutates its
  inputs.
- DECODE DEPTH IS BOUNDED (MAX_DECODE_DEPTH). Encodings beyond the bound are
  flagged, not silently consumed; the flags are part of the model so any
  matcher (pattern, ML feature, future 0B.2 slice) can see what happened.
- MALFORMED INPUTS ARE FLAGGED, NEVER FATAL: invalid percent escapes and
  invalid UTF-8 produce flags ('malformed-escape', 'malformed-utf8'), null
  bytes in decoded output produce 'null-byte'.
- PRIVACY LIMITS: only selected headers (user-agent, referer, content-type,
  x-forwarded-for) enter the canonical model, and cookie/header credential
  VALUES (Authorization, Cookie) never do - cookie NAMES only.
- SIZE AND CONTENT-TYPE LIMITS: URLs above MAX_URL_BYTES and bodies above
  MAX_BODY_BYTES are flagged and truncated/omitted; bodies are carried for
  SUPPORTED_BODY_TYPES (form-urlencoded, json, text/plain) and for bodies
  with no declared content type (flagged 'no-content-type' for visibility);
  explicitly declared unsupported types (e.g. binaries) are NEVER carried.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
from urllib.parse import unquote, unquote_plus

MAX_URL_BYTES = 8192
MAX_BODY_BYTES = 131072
MAX_DECODE_DEPTH = 3
MAX_HEADER_VALUE_BYTES = 4096

SUPPORTED_BODY_TYPES = frozenset(
    {
        "application/x-www-form-urlencoded",
        "application/json",
        "text/plain",
    }
)

SELECTED_HEADERS = (
    "user-agent",
    "referer",
    "content-type",
    "x-forwarded-for",
)

_MALFORMED_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


@dataclass(frozen=True)
class CanonicalRequest:
    method: str
    raw_url: str
    raw_path: str
    raw_query: str
    canonical_path: str
    canonical_query: str
    decode_depth: int = 0
    decode_flags: Tuple[str, ...] = ()
    headers: Dict[str, str] = field(default_factory=dict)
    cookie_names: Tuple[str, ...] = ()
    body_included: bool = False
    body_content_type: Optional[str] = None
    canonical_body: Optional[str] = None
    body_flags: Tuple[str, ...] = ()

    def inspection_text(self) -> str:
        """Everything a pattern matcher is allowed to see: raw AND canonical."""
        parts = [self.raw_url, self.canonical_path, self.canonical_query or ""]
        parts.extend(self.headers.values())
        if self.canonical_body:
            parts.append(self.canonical_body)
        return " ".join(p for p in parts if p)


def split_url(url: str) -> Tuple[str, str]:
    """Split a raw URL into (raw_path, raw_query). Neither form is decoded."""
    path, _, query = url.partition("?")
    return path, query


def _iterative_decode(text: str, form_plus: bool = False):
    """Percent-decode up to MAX_DECODE_DEPTH times.

    Returns (decoded_text, depth, flags). depth counts how many decode passes
    actually changed the text; >=2 means at least double-encoded. form_plus
    additionally treats '+' as a space (query strings / form bodies).
    """
    current = text
    depth = 0
    flags = set()
    if _MALFORMED_ESCAPE.search(text):
        flags.add("malformed-escape")
    for i in range(MAX_DECODE_DEPTH):
        decoded = (
            unquote_plus(current, errors="replace")
            if form_plus
            else unquote(current, errors="replace")
        )
        if decoded == current:
            break
        current = decoded
        depth = i + 1
        if depth >= 2:
            flags.add("double-encoded")
    if "\x00" in current:
        flags.add("null-byte")
    if "\ufffd" in current:
        flags.add("malformed-utf8")
    return current, depth, flags


def _canonical_query(raw_query: str) -> str:
    if not raw_query:
        return ""
    pairs = []
    for chunk in raw_query.split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        key_d, _, _ = _iterative_decode(key, form_plus=True)
        value_d, _, _ = _iterative_decode(value, form_plus=True)
        pairs.append(f"{key_d}={value_d}")
    return " ".join(pairs)


def canonicalize(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body=None,
    content_type: Optional[str] = None,
    method: str = "GET",
) -> CanonicalRequest:
    """Build the canonical request model for one request.

    url/headers/body are the RAW forms. content_type falls back to the
    Content-Type header. Nothing here raises on malformed input; problems
    surface as flags.
    """
    headers = headers or {}
    raw_url = url or ""
    flags: set = set()

    if len(raw_url.encode("utf-8", errors="replace")) > MAX_URL_BYTES:
        flags.add("url-too-large")
        raw_url = raw_url[:MAX_URL_BYTES]

    raw_path, raw_query = split_url(raw_url)
    canonical_path, depth_path, flags_path = _iterative_decode(raw_path)
    canonical_query, depth_query, flags_query = _iterative_decode(
        raw_query, form_plus=True
    )
    canonical_query = _canonical_query(raw_query)
    flags |= flags_path | flags_query
    depth = max(depth_path, depth_query)

    selected: Dict[str, str] = {}
    cookie_names: Tuple[str, ...] = ()
    for name, value in headers.items():
        lowered = str(name).lower()
        if lowered == "cookie":
            cookie_names = tuple(
                part.strip().partition("=")[0]
                for part in str(value).split(";")
                if part.strip()
            )
            continue
        if lowered in SELECTED_HEADERS:
            value_str = str(value)
            if len(value_str.encode("utf-8", errors="replace")) > MAX_HEADER_VALUE_BYTES:
                value_str = value_str[:MAX_HEADER_VALUE_BYTES]
                flags.add("header-value-truncated")
            selected[lowered] = value_str

    if content_type is None:
        content_type = selected.get("content-type", "")
    ct = str(content_type).partition(";")[0].strip().lower()

    body_included = False
    canonical_body = None
    body_flags: set = set()
    if body is not None:
        if ct and ct not in SUPPORTED_BODY_TYPES:
            body_flags.add("unsupported-content-type")
        else:
            if not ct:
                body_flags.add("no-content-type")
            if isinstance(body, bytes):
                body_text = body.decode("utf-8", errors="replace")
            else:
                body_text = str(body)
            if len(body_text.encode("utf-8", errors="replace")) > MAX_BODY_BYTES:
                body_flags.add("body-too-large")
            elif ct == "application/x-www-form-urlencoded":
                decoded_pairs = []
                for chunk in body_text.split("&"):
                    key, _, value = chunk.partition("=")
                    key_d, _, _ = _iterative_decode(key, form_plus=True)
                    value_d, _, _ = _iterative_decode(value, form_plus=True)
                    decoded_pairs.append(f"{key_d}={value_d}")
                canonical_body = " ".join(decoded_pairs)
                body_included = True
            elif ct == "application/json":
                try:
                    json.loads(body_text)
                except (ValueError, TypeError):
                    body_flags.add("malformed-json")
                canonical_body = body_text
                body_included = True
            else:  # text/plain, or a body with no declared content type
                canonical_body = body_text
                body_included = True

    return CanonicalRequest(
        method=str(method).upper(),
        raw_url=raw_url,
        raw_path=raw_path,
        raw_query=raw_query,
        canonical_path=canonical_path,
        canonical_query=canonical_query,
        decode_depth=depth,
        decode_flags=tuple(sorted(flags)),
        headers=selected,
        cookie_names=cookie_names,
        body_included=body_included,
        body_content_type=ct or None,
        canonical_body=canonical_body,
        body_flags=tuple(sorted(body_flags)),
    )
