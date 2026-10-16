"""
0A.13 - the SSH activation chain, EXECUTED against a real node (docker-marked).

WHY THIS FILE EXISTS
    The validate -> activate -> reload -> verify -> rollback chain lives in
    _ssh_deploy_sync (src/nginx_manager.py) and, until 0A.13, had NEVER EXECUTED
    ANYWHERE: the stock node image has no sshd, and the API built nodes with
    ssh_key_path=None so the transport raised ValueError('SSH key required')
    before connecting. A chain that has never run is not "done", however good it
    reads.

    These tests drive a real candidate through the REAL method against the
    REAL SSH-capable node built for 0A.13 (docker/nginx-node-1/Dockerfile), and
    assert on what nginx actually did. They are the acceptance test for 0A.13:

      (a) an INVALID candidate is rejected, rolled back, and the node is still
          reloadable afterwards; and
      (b) a VALID candidate appears in `nginx -T`'s agent-node_1 section AND the
          pattern returns 403 when requested live.

    Both halves are required. One without the other leaves the pipeline unproven.

HOW TO RUN
    The 0A.13 node must be up and reachable on SSH. From the repo root:

      docker compose build nginx-node-1
      docker compose up -d --no-deps nginx-node-1
      ./.venv/Scripts/python.exe -m pytest tests/test_ssh_activation.py -m docker -q

    Defaults (overridable by env):
      WAF_SSH_TEST_HOST   127.0.0.1
      WAF_SSH_TEST_PORT   2222        (compose publishes node 22 -> host 2222)
      WAF_SSH_TEST_USER   root
      WAF_SSH_TEST_KEY    docker/nginx-node-1/ssh/id_ed25519  (relative to repo root)

    Unlike the throwaway-container tests in test_deploy_behaviour.py, these tests
    require the RUNNING node, so they FAIL (not skip) if the node is unreachable:
    a green skip here would hide exactly the failure 0A.13 exists to surface.
"""

import os
import shutil
from pathlib import Path

import pytest

import paramiko


REPO_ROOT = Path(__file__).resolve().parent.parent

SSH_HOST = os.getenv("WAF_SSH_TEST_HOST", "127.0.0.1")
SSH_PORT = int(os.getenv("WAF_SSH_TEST_PORT", "2222"))
SSH_USER = os.getenv("WAF_SSH_TEST_USER", "root")
SSH_KEY = Path(os.getenv("WAF_SSH_TEST_KEY", REPO_ROOT / "docker" / "nginx-node-1" / "ssh" / "id_ed25519"))

# The node's HTTP port as published to the host (compose 8081:80).
HTTP_URL = os.getenv("WAF_SSH_TEST_HTTP", "http://127.0.0.1:8081")

# The destination the SSH transport computes for node_id "node_1" — this is what
# the vhost includes (docker/nginx-node-1/default.conf:34). It must be the path
# the chain writes to, otherwise the test would be exercising a different tree.
REMOTE_RULES_FILE = "/etc/nginx/waf-rules/agent-node_1/rules.conf"


def _docker_available() -> bool:
    return shutil.which("docker") is not None


DOCKER = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker is required for the SSH activation test",
)

docker = pytest.mark.docker


def _ssh_connect():
    """Open a paramiko SSH client to the 0A.13 node, or fail with the real error."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=SSH_HOST,
        port=SSH_PORT,
        username=SSH_USER,
        key_filename=str(SSH_KEY),
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
    )
    return ssh


def _remote_cmd(ssh, cmd, timeout=30):
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, (stdout.read().decode() or ""), (stderr.read().decode() or "")


def _cleanup_remote_rule(ssh):
    """Remove the agent rule file and reload, so no test rule lingers on the node."""
    try:
        sftp = ssh.open_sftp()
        try:
            sftp.remove(REMOTE_RULES_FILE)
        except (IOError, OSError):
            pass  # Already gone.
        finally:
            sftp.close()
        _remote_cmd(ssh, "nginx -s reload", timeout=30)
    except Exception:
        pass


def _loaded_section_has(ssh, needle: str) -> bool:
    """Whether `nginx -T` output contains `needle` anywhere (the file's section)."""
    code, out, _ = _remote_cmd(ssh, "nginx -T", timeout=30)
    if code != 0:
        return False
    return needle in out


def _live_status(path: str) -> int:
    """GET `path` on the published node and return the HTTP status (0 on error)."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(HTTP_URL + path, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


@pytest.fixture()
def ssh_node():
    """Connect to the 0A.13 node, fail (not skip) if it is unreachable."""
    if not _docker_available():
        pytest.skip("Docker is required for the SSH activation test")
    ssh = _ssh_connect()
    # Establish a clean baseline: no agent rule file, nginx healthy.
    _cleanup_remote_rule(ssh)
    yield ssh
    _cleanup_remote_rule(ssh)
    ssh.close()


def _run_real_deploy(candidate: str) -> bool:
    """Run the REAL _ssh_deploy_sync for node_1, opening its own connection."""
    from src.nginx_manager import NginxManager, NginxNode

    node = NginxNode(
        node_id="node_1",
        hostname=SSH_HOST,
        ssh_host=SSH_HOST,
        ssh_port=SSH_PORT,
        ssh_username=SSH_USER,
        ssh_key_path=str(SSH_KEY),
        nginx_config_path="/etc/nginx/conf.d",
        nginx_reload_command="nginx -s reload",
        api_endpoint=None,
    )
    manager = NginxManager([node])
    # _ssh_deploy_sync is sync; the transport wraps it in run_in_executor but the
    # method itself is the chain under test. Call it directly.
    return manager._ssh_deploy_sync(node, candidate)


@DOCKER
def test_invalid_candidate_is_rejected_and_node_still_reloadable(ssh_node):
    """0A.13(a): a bad candidate must be rejected, rolled back, and leave the node reloadable."""
    ssh = ssh_node

    # Deliberately invalid: a bare `if` whose condition is malformed (unbalanced),
    # so `nginx -t` fails.
    invalid = 'if ($request_uri ~ "(") { return 403; }\n'

    result = _run_real_deploy(invalid)

    # The chain must NOT report success for a config nginx refuses.
    assert result is False, "an invalid candidate must be rejected (result was True)"

    # The candidate must have been rolled back: its content must not remain loaded.
    assert not _loaded_section_has(ssh, 'if ($request_uri ~ "(")'), (
        "the rejected candidate's content must not remain in the loaded configuration"
    )

    # The node must still reload cleanly — the half that protects customer traffic.
    code, _, err = _remote_cmd(ssh, "nginx -t", timeout=30)
    assert code == 0, f"node must still be reloadable after rejection, got: {err}"


@DOCKER
def test_valid_candidate_is_activated_and_enforced(ssh_node):
    """0A.13(b): a valid candidate must appear in nginx -T and block the pattern live."""
    ssh = ssh_node

    # A valid rule at server scope: block requests whose URI contains /blockme.
    valid = 'if ($request_uri ~ "blockme") { return 403; }\n'

    # Baseline: the path is currently allowed (proves the rule is what blocks it).
    baseline = _live_status("/blockme")
    assert baseline in (200, 404), f"baseline /blockme should be allowed, got {baseline}"

    result = _run_real_deploy(valid)

    assert result is True, "a valid candidate must be reported as deployed and verified active"

    # The rule must appear in the loaded configuration.
    assert _loaded_section_has(ssh, 'if ($request_uri ~ "blockme") { return 403; }'), (
        "the deployed rule must appear in `nginx -T` output"
    )

    # The pattern must now be blocked live.
    #
    # nginx -s reload is ASYNCHRONOUS: it exits 0 once the master has parsed the
    # new config and signalled the workers, but the old workers keep serving until
    # they pick it up. Measured on this node: reload exits in ~24ms and the rule
    # becomes effective ~100ms later. Asserting 403 immediately after the call
    # races that window and fails on a correct deployment. Poll with a bounded
    # deadline instead.
    import time
    deadline = time.time() + 5.0
    blocked = _live_status("/blockme")
    while blocked != 403 and time.time() < deadline:
        time.sleep(0.05)
        blocked = _live_status("/blockme")
    assert blocked == 403, f"/blockme should now be blocked (403), got {blocked}"
