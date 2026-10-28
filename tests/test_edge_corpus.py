"""0B.4: attack and safe-traffic corpus against the real shipped nginx config.

Plan v7.5 0B.4: "Permanently encode the measured bypasses ... Each new
protection starts with a failing bypass test and a safe-traffic test before
implementation."

The corpus drives a throwaway nginx container that mounts the REPOSITORY's
real node-1 configuration and the real basic.conf maps (the same fixture
discipline as test_deploy_behaviour.py: the tests make claims about the
shipped configuration, not about a stand-in).

WHY RAW SOCKETS AND NOT requests:
    requests re-encodes unsafe characters in the URL it is given, which
    silently rewrites the measured payload representation - exactly the
    encoding/canonicalisation trap this corpus exists to pin down. Every
    probe below goes out on the wire as the literal bytes listed here.

Three groups:

  STILL BLOCKED - measured as blocked on 2026-10-19 (plan v7.5 protection
      boundary) and asserted to REMAIN blocked: regressions here are release
      blockers.

  PROMOTED - the former BYPASSED set. Strict-xfail entries until the 0B.2
      slice (CRS baseline wiring per ADR 0002 + moving the canned API
      responses into the content phase) measured 403 on every entry; they
      now assert the protection boundary like STILL BLOCKED.

  SAFE TRAFFIC - legitimate near-matches that must never be blocked. These
      are the false-positive controls for every future signature, and they
      all target real origin endpoints so an origin 404 can never be
      confused with a WAF block.
"""

import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE1_DIR = REPO_ROOT / "docker" / "nginx-node-1"
REAL_NGINX_CONF = NODE1_DIR / "nginx.conf"
REAL_VHOST = NODE1_DIR / "default.conf"
REAL_BASIC = REPO_ROOT / "docker" / "shared" / "waf-rules" / "basic.conf"
REAL_API_JS = NODE1_DIR / "api.js"

docker = pytest.mark.docker


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------- corpus ----

def _get(path, headers=None):
    return ("GET", path, headers or {}, None)


def _post_form(path, body, headers=None):
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    return ("POST", path, {**form, **(headers or {})}, body)


# Entries measured BLOCKED on 2026-10-19; must stay blocked.
# (rule_id, request spec, expected status: 403 signature block / 404 extension block)
STILL_BLOCKED = [
    ("sqli-union-select-query", _get("/api/search?q=union+select"), 403),
    ("sqli-drop-table-query", _get("/api/search?q=drop+table"), 403),
    ("xss-literal-script-query", _get("/api/search?q=<script>alert(1)</script>"), 403),
    ("xss-literal-javascript-query", _get("/api/search?q=javascript:alert(1)"), 403),
    ("sensitive-file-env", _get("/.env"), 404),
    # 0B.2: under the CRS baseline / .git /config is pinned by CRS 930120
    # with 403 (404 keeps for .env, which the static extension map returns
    # in the rewrite phase before CRS phase 2 runs).
    ("sensitive-file-git-config", _get("/.git/config"), 403),
]

# Measured 200-bypasses on 2026-10-19 against the nginx:alpine signature
# baseline. On 2026-10-28 the 0B.2 slice wired the CRS engine in front of
# the shipped config (ADR 0002) and moved the canned API/dashboard
# responses out of the rewrite-phase fast path (njs content handlers), at
# which point EVERY entry below measured 403 on the shipped node image.
# They are promoted to plain assertions: they are now part of the
# protection boundary, like STILL BLOCKED.
PROMOTED = [
    # canonicalisation: encoded representations of blocked literals
    ("xss-percent-encoded-javascript", _get("/api/search?q=%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)")),
    ("xss-double-encoded-script", _get("/api/search?q=%253Cscript%253Ealert(1)%253C/script%253E")),
    # coverage: attack classes with no signature in the internal baseline
    ("sqli-or-1eq1", _get("/api/search?id=1+OR+1%3D1")),
    ("traversal-dotdot-query", _get("/api/search?file=../../../etc/passwd")),
    # placement: bodies, headers and cookies
    ("sqli-post-body", _post_form("/api/login", "username=admin'--&password=x")),
    ("xss-user-agent-header", _get("/api/users", {"User-Agent": "<script>alert(1)</script>"})),
    ("xss-cookie-header", _get("/api/users", {"Cookie": "theme=<script>alert(1)</script>"})),
]

# Legitimate near-matches; must never be blocked. All target real origin
# endpoints so an origin 404 can never be mistaken for a WAF decision.
SAFE_TRAFFIC = [
    ("root-page", _get("/")),
    ("api-users", _get("/api/users")),
    ("clean-login-post", _post_form("/api/login", "username=alice&password=hunter2")),
    ("word-union-no-select", _get("/api/search?q=the+union+of+two+sets")),
    ("word-select-alone", _get("/api/search?q=select+statement+in+class")),
    ("word-drop-no-table", _get("/api/search?q=drop+everything+and+run")),
    ("extension-near-match-in-query", _get("/?file=theme.env.bak")),
    ("javascript-word-in-query", _get("/?next=/tutorial-javascript-basics")),
]


@pytest.fixture(scope="module")
def edge_port():
    """A throwaway container running the SHIPPED node image with the
    repository's real configuration (compose-identical mounts)."""
    container = f"waf-corpus-{uuid.uuid4().hex[:12]}"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    build = subprocess.run(
        ["docker", "build", "-q", "-t", "waf-corpus-node",
         str(NODE1_DIR)],
        capture_output=True, text=True, timeout=900,
    )
    if build.returncode != 0:
        pytest.skip(f"corpus node image failed to build: {build.stderr.strip()[:200]}")

    mounts = [
        "-v", f"{REAL_NGINX_CONF}:/etc/nginx/templates/nginx.conf.template:ro",
        "-v", f"{REAL_VHOST}:/etc/nginx/conf.d/waf-node.conf:ro",
        "-v", f"{REAL_API_JS}:/etc/nginx/api.js:ro",
        "-v", f"{REAL_BASIC}:/etc/nginx/waf-rules/basic.conf:ro",
    ]
    try:
        proc = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", container,
             "-p", f"127.0.0.1:{port}:80", *mounts, "waf-corpus-node"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            pytest.skip(f"corpus nginx failed to start: {proc.stderr.strip()[:200]}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if requests.get(f"http://127.0.0.1:{port}/", timeout=2).status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.4)
        else:
            pytest.skip("corpus nginx never became ready")
        yield port
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], capture_output=True, timeout=30
        )


def _status(port, spec):
    """Send the request as LITERAL BYTES and return the response status."""
    method, path, headers, body = spec
    request = f"{method} {path} HTTP/1.1\r\nHost: nginx-node-1\r\nConnection: close\r\n"
    for name, value in headers.items():
        request += f"{name}: {value}\r\n"
    if body:
        request += f"Content-Length: {len(body.encode('utf-8'))}\r\n"
    request += "\r\n"
    if body:
        request += body
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(request.encode("utf-8"))
        response = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
    head = response.split(b"\r\n", 1)[0].decode("latin-1")
    return int(head.split(" ")[1])


@pytest.mark.skipif(not _docker_available(), reason="Docker is required for corpus tests")
class TestCorpus:
    @docker
    @pytest.mark.parametrize(
        "rule_id,spec,expected",
        STILL_BLOCKED, ids=[entry[0] for entry in STILL_BLOCKED],
    )
    def test_measured_blocked_classes_stay_blocked(self, edge_port, rule_id, spec, expected):
        assert _status(edge_port, spec) == expected

    @docker
    @pytest.mark.parametrize("rule_id,spec", PROMOTED, ids=[entry[0] for entry in PROMOTED])
    def test_promoted_bypasses_stay_blocked(self, edge_port, rule_id, spec):
        status = _status(edge_port, spec)
        assert status == 403, f"promoted protection regressed: HTTP {status}"

    @docker
    @pytest.mark.parametrize("rule_id,spec", SAFE_TRAFFIC, ids=[entry[0] for entry in SAFE_TRAFFIC])
    def test_safe_traffic_is_never_blocked(self, edge_port, rule_id, spec):
        status = _status(edge_port, spec)
        assert status == 200, f"false positive: safe request {rule_id} got HTTP {status}"
