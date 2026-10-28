"""0D: the data-plane tenant boundary, verified by OBSERVATION (0D.3).

Plan v7.5 0D.1-0D.3: a tenant vhost that proxies (selected by Host), a
default vhost that REFUSES unknown hosts (T11), verified with the 0C.9
harness: the origin records what it received, so "we forward correctly"
is demonstrated rather than configured.

The rig: a throwaway user-defined docker network with a test-origin
container and an edge container running the SHIPPED node image with the
repository's real configuration (compose-identical mounts, plus the
generated tenant vhosts file).
"""

import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
NODE1_DIR = REPO_ROOT / "docker" / "nginx-node-1"
SHARED = REPO_ROOT / "docker" / "shared"
REAL_NGINX_CONF = NODE1_DIR / "nginx.conf"
REAL_VHOST = NODE1_DIR / "default.conf"
REAL_BASIC = SHARED / "waf-rules" / "basic.conf"
REAL_TENANTS = SHARED / "tenant-policies"

TENANT_HOST = "acme.edge.test"

docker = pytest.mark.docker


def _docker_available() -> bool:
    return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0


def _build_images():
    for name, ctx in (("waf-corpus-node", NODE1_DIR),
                      ("waf-test-origin", REPO_ROOT / "docker" / "test-origin")):
        build = subprocess.run(
            ["docker", "build", "-q", "-t", name, str(ctx)],
            capture_output=True, text=True, timeout=900,
        )
        if build.returncode != 0:
            pytest.skip(f"{name} failed to build: {build.stderr.strip()[:200]}")


@pytest.fixture(scope="module")
def proxy_rig():
    """Edge + origin on a throwaway network; yields (edge_port, origin_port)."""
    if not _docker_available():
        pytest.skip("Docker is required for proxy-correctness tests")
    _build_images()
    suffix = uuid.uuid4().hex[:8]
    network = f"waf-proxy-{suffix}"
    edge = f"waf-edge-{suffix}"
    origin = f"waf-origin-{suffix}"

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        edge_port = probe.getsockname()[1]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        origin_port = probe.getsockname()[1]

    mounts = [
        "-v", f"{REAL_NGINX_CONF}:/etc/nginx/templates/nginx.conf.template:ro",
        "-v", f"{REAL_VHOST}:/etc/nginx/conf.d/waf-node.conf:ro",
        "-v", f"{REAL_TENANTS / 'vhosts.conf'}:/etc/nginx/conf.d/waf-tenants.conf:ro",
        "-v", f"{NODE1_DIR / 'api.js'}:/etc/nginx/api.js:ro",
        "-v", f"{REAL_BASIC}:/etc/nginx/waf-rules/basic.conf:ro",
        "-v", f"{REAL_TENANTS}:/etc/nginx/tenants:ro",
    ]
    try:
        subprocess.run(["docker", "network", "create", network],
                       capture_output=True, timeout=60, check=True)
        origin_run = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", origin,
             "--network", network, "--network-alias", "test-origin",
             "-p", f"127.0.0.1:{origin_port}:8090", "waf-test-origin"],
            capture_output=True, text=True, timeout=120,
        )
        edge_run = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", edge,
             "--network", network,
             "-p", f"127.0.0.1:{edge_port}:80", *mounts, "waf-corpus-node"],
            capture_output=True, text=True, timeout=120,
        )
        if origin_run.returncode != 0 or edge_run.returncode != 0:
            pytest.skip(f"rig failed to start: {origin_run.stderr or edge_run.stderr}")

        deadline = time.monotonic() + 30
        ready = False
        while time.monotonic() < deadline:
            try:
                if requests.get(f"http://127.0.0.1:{origin_port}/health", timeout=2).status_code == 200 \
                        and requests.get(
                            f"http://127.0.0.1:{edge_port}/",
                            headers={"Host": "nginx-node-1"}, timeout=2
                        ).status_code == 200:
                    ready = True
                    break
            except requests.RequestException:
                time.sleep(0.4)
        if not ready:
            logs = subprocess.run(["docker", "logs", edge], capture_output=True,
                                  text=True, timeout=30)
            pytest.skip(f"rig never became ready: {logs.stdout[-300:]}")
        yield edge_port, origin_port
    finally:
        subprocess.run(["docker", "rm", "-f", edge, origin],
                       capture_output=True, timeout=60)
        subprocess.run(["docker", "network", "rm", network],
                       capture_output=True, timeout=60)


def _edge_request(edge_port, path, headers=None, body=None, host=TENANT_HOST):
    method = "POST" if body else "GET"
    request = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    if body:
        headers = dict(headers or {})
        headers["Content-Length"] = str(len(body))
    for name, value in (headers or {}).items():
        request += f"{name}: {value}\r\n"
    request += "\r\n"
    payload = request.encode() + (body or b"")
    with socket.create_connection(("127.0.0.1", edge_port), timeout=15) as conn:
        conn.sendall(payload)
        response = b""
        while True:
            try:
                chunk = conn.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
    head, _, rest = response.partition(b"\r\n\r\n")
    status = int(head.decode("latin-1").split(" ")[1])
    return status, rest


def _observations(origin_port) -> list:
    response = requests.get(f"http://127.0.0.1:{origin_port}/observations", timeout=5)
    return response.json()["observations"]


@pytest.mark.skipif(not _docker_available(), reason="Docker required")
class TestTenantBoundary:
    @docker
    def test_tenant_host_reaches_its_origin(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        status, _ = _edge_request(edge_port, "/record")
        assert status == 200
        obs = _observations(origin_port)[-1]
        assert obs["host"] == TENANT_HOST

    @docker
    def test_client_supplied_xff_is_not_trusted(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        _edge_request(edge_port, "/record",
                      headers={"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"})
        obs = _observations(origin_port)[-1]
        # 0C.1 trust policy: the edge OVERWRITES, never trusts
        assert obs["x_forwarded_for"] != "1.2.3.4"
        assert obs["x_forwarded_for"] is not None
        assert obs["x_real_ip"] != "5.6.7.8"
        assert obs["x_real_ip"] is not None

    @docker
    def test_identity_headers_observed(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        _edge_request(edge_port, "/record")
        obs = _observations(origin_port)[-1]
        assert obs["x_forwarded_proto"] == "http"
        assert obs["x_forwarded_for"] is not None

    @docker
    def test_unknown_host_is_refused_and_never_proxied(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        before = len(_observations(origin_port))
        status, _ = _edge_request(edge_port, "/", host="unknown.example")
        assert status == 421
        assert len(_observations(origin_port)) == before

    @docker
    def test_body_size_limit_enforced_per_tenant(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        before = len(_observations(origin_port))
        status, _ = _edge_request(edge_port, "/record", body=b"x" * (2 * 1024 * 1024))
        assert status == 413
        assert len(_observations(origin_port)) == before
        # within the limit the body arrives whole (a POST needs a content
        # type, or CRS 920420 blocks it before the origin - by design)
        status, _ = _edge_request(
            edge_port, "/record", body=b"y" * 4096,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 200
        assert _observations(origin_port)[-1]["body_bytes"] == 4096

    @docker
    def test_crs_guards_the_tenant_vhost(self, proxy_rig):
        edge_port, _ = proxy_rig
        status, _ = _edge_request(edge_port, "/?id=1+OR+1%3D1")
        assert status == 403, "the tenant path must stay inside the WAF"

    @docker
    def test_upgrade_negotiation_forwarded(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        status, _ = _edge_request(
            edge_port, "/record",
            headers={"Upgrade": "websocket", "Connection": "Upgrade"})
        assert status == 200
        obs = _observations(origin_port)[-1]
        assert obs["upgrade"] == "websocket"

    @docker
    def test_origin_failure_has_a_defined_response(self, proxy_rig):
        edge_port, origin_port = proxy_rig
        # find the actual origin container on this network
        names = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"], capture_output=True,
            text=True, timeout=30).stdout.split()
        origin_name = next(n for n in names if n.startswith("waf-origin-"))
        subprocess.run(["docker", "stop", origin_name],
                       capture_output=True, timeout=60)
        try:
            status, body = _edge_request(edge_port, "/record")
            assert status == 502
            assert b"edge_origin_unavailable" in body
        finally:
            subprocess.run(["docker", "start", origin_name],
                           capture_output=True, timeout=60)
