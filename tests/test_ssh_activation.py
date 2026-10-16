"""
0A.13 - the SSH activation chain, EXECUTED against real nodes (docker-marked).

WHY THIS FILE EXISTS
    The validate -> activate -> reload -> verify -> rollback chain lives in
    _ssh_deploy_sync (src/nginx_manager.py) and, until 0A.13, had NEVER EXECUTED
    ANYWHERE: the stock node image has no sshd, and the API built nodes with
    ssh_key_path=None so the transport raised ValueError('SSH key required')
    before connecting. A chain that has never run is not "done", however good it
    reads.

    These tests drive a real candidate through the REAL method against the
    REAL SSH-capable nodes built for 0A.13 (docker/nginx-node-1/Dockerfile, shared
    by both node_1 and node_2), and assert on what nginx actually did. They are
    the acceptance test for 0A.13:

      (a) an INVALID candidate is rejected, rolled back, and the node is still
          reloadable afterwards; and
      (b) a VALID candidate appears in `nginx -T`'s agent-<node> section AND the
          pattern returns 403 when requested live.

    Both halves are required, on BOTH nodes, because the multi-tenant safety
    boundary is per-node: a chain that works on node_1 but not node_2 would leave
    one tenant unprotected and none of the deploy paths would notice.

HOW TO RUN
    Both 0A.13 nodes must be up and reachable on SSH. From the repo root:

      docker compose build nginx-node-1 nginx-node-2
      docker compose up -d --no-deps nginx-node-1 nginx-node-2
      ./.venv/Scripts/python.exe -m pytest tests/test_ssh_activation.py -q

    Defaults (overridable by env):
      WAF_SSH_TEST_HOST   127.0.0.1
      WAF_SSH_TEST_USER   root
      WAF_SSH_TEST_KEY    docker/nginx-node-1/ssh/id_ed25519  (relative to repo root)

    Unlike the throwaway-container tests in test_deploy_behaviour.py, these tests
    require the RUNNING nodes, so they FAIL (not skip) if a node is unreachable:
    a green skip here would hide exactly the failure 0A.13 exists to surface.
"""

import os
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import paramiko


REPO_ROOT = Path(__file__).resolve().parent.parent

SSH_HOST = os.getenv("WAF_SSH_TEST_HOST", "127.0.0.1")
SSH_USER = os.getenv("WAF_SSH_TEST_USER", "root")
SSH_KEY = Path(os.getenv("WAF_SSH_TEST_KEY", REPO_ROOT / "docker" / "nginx-node-1" / "ssh" / "id_ed25519"))

# Per-node facts, as the compose file publishes them. The remote rules path is
# what the SSH transport computes for each node_id and what the vhost includes
# (docker/nginx-node-1/default.conf:34 and docker/nginx-node-2/default.conf:34).
NODE_SPECS = {
    "node_1": {
        "ssh_port": 2222,
        "http_url": "http://127.0.0.1:8081",
        "remote_rules": "/etc/nginx/waf-rules/agent-node_1/rules.conf",
    },
    "node_2": {
        "ssh_port": 2223,
        "http_url": "http://127.0.0.1:8082",
        "remote_rules": "/etc/nginx/waf-rules/agent-node_2/rules.conf",
    },
}


def _docker_available() -> bool:
    return shutil.which("docker") is not None


DOCKER = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker is required for the SSH activation test",
)

docker = pytest.mark.docker


def _ssh_connect(spec):
    """Open a paramiko SSH client to the given node, or fail with the real error."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=SSH_HOST,
        port=spec["ssh_port"],
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


def _cleanup_remote_rule(ssh, spec):
    """Remove the agent rule file and reload, so no test rule lingers on the node."""
    try:
        sftp = ssh.open_sftp()
        try:
            sftp.remove(spec["remote_rules"])
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


def _live_status(http_url: str, path: str) -> int:
    """GET `path` on the published node and return the HTTP status (0 on error)."""
    try:
        with urllib.request.urlopen(http_url + path, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


@pytest.fixture(params=list(NODE_SPECS.keys()), ids=list(NODE_SPECS.keys()))
def ssh_node(request):
    """Connect to one 0A.13 node, fail (not skip) if it is unreachable."""
    if not _docker_available():
        pytest.skip("Docker is required for the SSH activation test")
    node_id = request.param
    spec = NODE_SPECS[node_id]
    ssh = _ssh_connect(spec)
    # Establish a clean baseline: no agent rule file, nginx healthy.
    _cleanup_remote_rule(ssh, spec)
    yield node_id, ssh, spec
    _cleanup_remote_rule(ssh, spec)
    ssh.close()


def _run_real_deploy(node_id: str, spec, candidate: str) -> bool:
    """Run the REAL _ssh_deploy_sync for the named node, opening its own connection."""
    from src.nginx_manager import NginxManager, NginxNode

    node = NginxNode(
        node_id=node_id,
        hostname=SSH_HOST,
        ssh_host=SSH_HOST,
        ssh_port=spec["ssh_port"],
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
    node_id, ssh, spec = ssh_node

    # Deliberately invalid: a bare `if` whose condition is malformed (unbalanced),
    # so `nginx -t` fails.
    invalid = 'if ($request_uri ~ "(") { return 403; }\n'

    result = _run_real_deploy(node_id, spec, invalid)

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
    node_id, ssh, spec = ssh_node

    # A valid rule at server scope: block requests whose URI contains /blockme.
    valid = 'if ($request_uri ~ "blockme") { return 403; }\n'

    # Baseline: the path is currently allowed (proves the rule is what blocks it).
    baseline = _live_status(spec["http_url"], "/blockme")
    assert baseline in (200, 404), f"baseline /blockme should be allowed, got {baseline}"

    result = _run_real_deploy(node_id, spec, valid)

    assert result is True, "a valid candidate must be reported as deployed and verified active"

    # The rule must appear in the loaded configuration.
    assert _loaded_section_has(ssh, 'if ($request_uri ~ "blockme") { return 403; }'), (
        "the deployed rule must appear in `nginx -T` output"
    )

    # The pattern must now be blocked live.
    #
    # nginx -s reload is ASYNCHRONOUS: it exits 0 once the master has parsed the
    # new config and signalled the workers, but the old workers keep serving until
    # they pick it up. Measured: reload exits in ~24ms and the rule becomes
    # effective ~100ms later. Asserting 403 immediately after the call races that
    # window and fails on a correct deployment. Poll with a bounded deadline.
    deadline = time.time() + 5.0
    blocked = _live_status(spec["http_url"], "/blockme")
    while blocked != 403 and time.time() < deadline:
        time.sleep(0.05)
        blocked = _live_status(spec["http_url"], "/blockme")
    assert blocked == 403, f"/blockme should now be blocked (403), got {blocked}"
