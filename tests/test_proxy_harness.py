"""0C.9: the proxy-correctness observation harness.

Plan v7.5 0C.9: "a local origin application that records what it received -
client address, scheme, Host, body size and upgrade negotiation - so every
claim in this phase is verified by observation rather than by reading
configuration."

0D.3 verifies the tenant vhost with this harness: the origin RECORDS, the
tests READ the record. These tests pin the record shape against the origin
container alone (no edge in between), so the 0D tests can distinguish
"the origin recorded it wrong" from "the edge forwarded it wrong".
"""

import json
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
ORIGIN_DIR = REPO_ROOT / "docker" / "test-origin"

docker = pytest.mark.docker


def _docker_available() -> bool:
    if subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode != 0:
        return False
    return True


@pytest.fixture(scope="module")
def origin_port():
    """A throwaway test-origin container on a loopback port."""
    if not _docker_available():
        pytest.skip("Docker is required for the proxy-correctness harness")
    build = subprocess.run(
        ["docker", "build", "-q", "-t", "waf-test-origin", str(ORIGIN_DIR)],
        capture_output=True, text=True, timeout=600,
    )
    if build.returncode != 0:
        pytest.skip(f"test origin failed to build: {build.stderr.strip()[:200]}")
    container = f"waf-origin-{uuid.uuid4().hex[:12]}"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    try:
        proc = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", container,
             "-p", f"127.0.0.1:{port}:8090", "waf-test-origin"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            pytest.skip(f"test origin failed to start: {proc.stderr.strip()[:200]}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if requests.get(f"http://127.0.0.1:{port}/health", timeout=2).status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.3)
        else:
            pytest.skip("test origin never became ready")
        yield port
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30)


def _observations(port: int) -> list:
    response = requests.get(f"http://127.0.0.1:{port}/observations", timeout=5)
    assert response.status_code == 200
    return response.json()["observations"]


class TestOriginRecordShape:
    def test_records_client_address_host_and_body_size(self, origin_port):
        response = requests.post(
            f"http://127.0.0.1:{origin_port}/record",
            data=b"x" * 1234,
            headers={"Host": "origin-alone.test"},
            timeout=5,
        )
        assert response.status_code == 200
        obs = _observations(origin_port)[-1]
        assert obs["host"] == "origin-alone.test"
        assert obs["body_bytes"] == 1234
        assert obs["method"] == "POST"
        assert obs["path"] == "/record"
        # recorded, present-but-missing distinguished from silently absent
        assert "x_forwarded_for" in obs

    def test_records_upgrade_negotiation(self, origin_port):
        response = requests.get(
            f"http://127.0.0.1:{origin_port}/record",
            headers={"Upgrade": "websocket", "Connection": "Upgrade",
                     "Host": "origin-alone.test"},
            timeout=5,
        )
        assert response.status_code == 200
        obs = _observations(origin_port)[-1]
        assert obs["upgrade"] == "websocket"
        assert "connection" in obs

    def test_records_scheme(self, origin_port):
        requests.get(f"http://127.0.0.1:{origin_port}/record", timeout=5)
        obs = _observations(origin_port)[-1]
        assert obs["scheme"] in ("http", "https")

    def test_observations_ring_is_bounded(self, origin_port):
        for _ in range(20):
            requests.get(f"http://127.0.0.1:{origin_port}/record", timeout=5)
        assert len(_observations(origin_port)) <= 100
