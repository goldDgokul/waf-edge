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
REAL_TENANTS = REPO_ROOT / "docker" / "shared" / "tenant-policies"
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
# The labeled corpus lives in src/edge_corpus.py so the published
# measurement (src/edge_measurement.py, docs/guide/measurement.md) and this
# regression gate consume the SAME data. The measured-history commentary
# lives with the data.

from src.edge_corpus import PROMOTED, SAFE_TRAFFIC
from src.edge_corpus import BLOCKED as STILL_BLOCKED

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
        "-v", f"{REAL_TENANTS}:/etc/nginx/tenants:ro",
        "-v", f"{REAL_TENANTS / 'vhosts.conf'}:/etc/nginx/conf.d/waf-tenants.conf:ro",
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
                # 0D.2: the default server refuses unknown Hosts, so the
                # readiness probe must name the demo vhost explicitly.
                if requests.get(f"http://127.0.0.1:{port}/",
                                headers={"Host": "nginx-node-1"},
                                timeout=2).status_code == 200:
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
    @pytest.mark.parametrize("entry", STILL_BLOCKED, ids=[e.rule_id for e in STILL_BLOCKED])
    def test_measured_blocked_classes_stay_blocked(self, edge_port, entry):
        assert _status(edge_port, entry.spec) == entry.expected_status

    @docker
    @pytest.mark.parametrize("entry", PROMOTED, ids=[e.rule_id for e in PROMOTED])
    def test_promoted_bypasses_stay_blocked(self, edge_port, entry):
        status = _status(edge_port, entry.spec)
        assert status == 403, f"promoted protection regressed: HTTP {status}"

    @docker
    @pytest.mark.parametrize("entry", SAFE_TRAFFIC, ids=[e.rule_id for e in SAFE_TRAFFIC])
    def test_safe_traffic_is_never_blocked(self, edge_port, entry):
        status = _status(edge_port, entry.spec)
        assert status == 200, f"false positive: safe request {entry.rule_id} got HTTP {status}"
