"""The labeled edge corpus as shared data (plan v7.5 0B.4/0B.5).

The corpus is the single source of truth for both the regression gate
(tests/test_edge_corpus.py) and the published per-class measurement
(src/edge_measurement.py, docs/guide/measurement.md). Every entry carries
the attack class it represents and the protection placement that pins it,
so per-class and per-placement metrics can be computed without
re-deriving them from the test module.

WHY RAW-SOCKET SPECS AND NOT requests OBJECTS:
    requests re-encodes unsafe characters in the URL it is given, which
    silently rewrites the measured payload representation - exactly the
    encoding/canonicalisation trap this corpus exists to pin down. Specs
    here are literal wire bytes: (method, path, headers, body).
"""

from dataclasses import dataclass, field
from typing import Optional

Spec = tuple  # (method, path, headers dict, body or None)


def get(path: str, headers: Optional[dict] = None) -> Spec:
    return ("GET", path, dict(headers or {}), None)


def post_form(path: str, body: str) -> Spec:
    return ("POST", path, {"Content-Type": "application/x-www-form-urlencoded"}, body)


@dataclass(frozen=True)
class Entry:
    rule_id: str
    attack_class: str      # sqli / xss / traversal / sensitive-file / legitimate
    placement: str         # crs / static-extension-map / njs-content
    spec: Spec
    expected_status: int


@dataclass(frozen=True)
class Corpus:
    blocked: tuple = field(default=())
    safe: tuple = field(default=())

    @property
    def entries(self):
        return list(self.blocked) + list(self.safe)

    @property
    def attack_count(self) -> int:
        return len(self.blocked)

    @property
    def safe_count(self) -> int:
        return len(self.safe)


# Measured blocked on 2026-10-19 (nginx:alpine signature baseline) and
# re-measured blocked on 2026-10-28 under the CRS baseline; regressions
# here are release blockers.
BLOCKED = (
    Entry("sqli-union-select-query", "sqli", "crs",
          get("/api/search?q=union+select"), 403),
    Entry("sqli-drop-table-query", "sqli", "crs",
          get("/api/search?q=drop+table"), 403),
    Entry("xss-literal-script-query", "xss", "crs",
          get("/api/search?q=<script>alert(1)</script>"), 403),
    Entry("xss-literal-javascript-query", "xss", "crs",
          get("/api/search?q=javascript:alert(1)"), 403),
    # .env stays a 404: the static extension map blocks it in the rewrite
    # phase, before CRS phase 2 runs.
    Entry("sensitive-file-env", "sensitive-file", "static-extension-map",
          get("/.env"), 404),
    # 0B.2: under the CRS baseline /.git/config is pinned by CRS 930120
    # with 403 (previously a 404 from the static map).
    Entry("sensitive-file-git-config", "sensitive-file", "crs",
          get("/.git/config"), 403),
)

# Former measured 200-bypasses (2026-10-19, nginx:alpine signature
# baseline). The 0B.2 slice (CRS wiring per ADR 0002 + moving the canned
# API/dashboard responses into njs content handlers) measured 403 on
# every entry; they are now part of the protection boundary like BLOCKED.
PROMOTED = (
    # canonicalisation: encoded representations of blocked literals
    Entry("xss-percent-encoded-javascript", "xss", "crs",
          get("/api/search?q=%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)"), 403),
    Entry("xss-double-encoded-script", "xss", "crs",
          get("/api/search?q=%253Cscript%253Ealert(1)%253C/script%253E"), 403),
    # coverage: attack classes with no signature in the internal baseline
    Entry("sqli-or-1eq1", "sqli", "crs",
          get("/api/search?id=1+OR+1%3D1"), 403),
    Entry("traversal-dotdot-query", "traversal", "crs",
          get("/api/search?file=../../../etc/passwd"), 403),
    # placement: bodies, headers and cookies (CRS phase 2 inspects them
    # through the njs content handlers)
    Entry("sqli-post-body", "sqli", "crs",
          post_form("/api/login", "username=admin'--&password=x"), 403),
    Entry("xss-user-agent-header", "xss", "crs",
          get("/api/users", {"User-Agent": "<script>alert(1)</script>"}), 403),
    Entry("xss-cookie-header", "xss", "crs",
          get("/api/users", {"Cookie": "theme=<script>alert(1)</script>"}), 403),
)

# Legitimate near-matches; must never be blocked. These are the
# false-positive controls for every future signature. All target real
# origin endpoints so an origin 404 can never be mistaken for a WAF
# decision.
SAFE_TRAFFIC = (
    Entry("root-page", "legitimate", "njs-content", get("/"), 200),
    Entry("api-users", "legitimate", "njs-content", get("/api/users"), 200),
    Entry("clean-login-post", "legitimate", "njs-content",
          post_form("/api/login", "username=alice&password=hunter2"), 200),
    Entry("word-union-no-select", "legitimate", "njs-content",
          get("/api/search?q=the+union+of+two+sets"), 200),
    Entry("word-select-alone", "legitimate", "njs-content",
          get("/api/search?q=select+statement+in+class"), 200),
    Entry("word-drop-no-table", "legitimate", "njs-content",
          get("/api/search?q=drop+everything+and+run"), 200),
    Entry("extension-near-match-in-query", "legitimate", "njs-content",
          get("/?file=theme.env.bak"), 200),
    Entry("javascript-word-in-query", "legitimate", "njs-content",
          get("/?next=/tutorial-javascript-basics"), 200),
)

EDGE_CORPUS = Corpus(blocked=BLOCKED + PROMOTED, safe=SAFE_TRAFFIC)

ENTRY_COUNT = len(EDGE_CORPUS.entries)
ATTACK_ENTRY_COUNT = EDGE_CORPUS.attack_count
SAFE_ENTRY_COUNT = EDGE_CORPUS.safe_count
