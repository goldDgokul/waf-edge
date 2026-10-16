"""
Tests for honest deployment semantics in NginxManager (plan item 0A.2/0A.4).

WHY THIS FILE EXISTS
    `_deploy_via_file()` wrote the rule file, *tried* to reload nginx with
    `docker exec <node> nginx -s reload`, logged a warning when that failed, and
    then returned True regardless. `_deploy_to_node()` returns as soon as that
    path reports success, so the only paths that validate the candidate with a
    real `nginx -t`, back up, reload, verify and roll back
    (`_deploy_via_api`, `_deploy_via_ssh`) were never reached.

    Consequences, reproduced live on 13 October:
      - a deployment returned HTTP 200 {"node_1": true, "node_2": true} while
        the configuration was invalid and no reload had occurred;
      - a valid rule was written but never loaded, so it did not block.

    The fault is that "staged" (written to disk) and "active" (loaded by nginx)
    were reported as the same thing. They are not.
"""

import inspect
import subprocess

import pytest

from src.nginx_manager import NginxManager, NginxNode


def _node():
    return NginxNode(
        node_id="node_1",
        hostname="node_1",
        ssh_host="node_1",
        ssh_port=22,
        ssh_username="root",
        ssh_key_path=None,
        nginx_config_path="/etc/nginx/conf.d",
        nginx_reload_command="nginx -s reload",
    )


class _Completed:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""


def _fake_run(returncode, stderr=""):
    """
    Build a subprocess.run replacement.

    The state is passed as DEFAULT ARGUMENTS because the method under test does
    `import subprocess` inside its own body: a lambda defined here cannot resolve
    this module's globals, and would raise NameError when called.
    """
    def _run(*args, _rc=returncode, _err=stderr, **kwargs):
        return _Completed(_rc, _err)
    return _run


def _redirect_shared_dir(tmp_path):
    """
    Point the shared-rules volume path at a temp dir.

    Works with whichever shape the implementation uses, so the test states the
    required BEHAVIOUR rather than dictating internals.
    """
    import src.nginx_manager as m

    for name in ("SHARED_WAF_DIR", "WAF_RULES_DIR"):
        if hasattr(m, name):
            setattr(m, name, str(tmp_path))
            return True
    return False


# -----------------------------------------------------------------------------
# The invariant: a write that is not loaded is not a deployment
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reload_failure_is_not_reported_as_success(tmp_path, monkeypatch):
    """
    RED before the fix: the file was written, the reload failed, and the method
    still returned True - so the caller believed the rules were live.
    """
    manager = NginxManager([])
    if not _redirect_shared_dir(tmp_path):
        pytest.skip("shared rules directory is not exposed as module state")

    monkeypatch.setattr(
        subprocess, "run",
        _fake_run(1, "docker: executable file not found"),
    )

    ok = await manager._deploy_via_file(_node(), "# rules\n")

    assert ok is False, (
        "a write whose reload failed was reported as a successful deployment; "
        "the caller will believe the rules are active when they are not"
    )


@pytest.mark.asyncio
async def test_successful_reload_is_not_treated_as_activation(tmp_path, monkeypatch):
    """
    A successful reload must NOT be read as "the rules are active".

    UPDATED for the Step 3 rebuild. This test previously asserted the OPPOSITE:
    that a reload returning 0 made _deploy_via_file return True. That is the
    false-success defect. `nginx -s reload` only reports that a signal was
    delivered - it returns 0 even for an invalid configuration, and it says
    nothing about whether the candidate was ever parsed.

    The file transport has no way to validate or reload the node at all (no
    docker CLI, no socket, no nginx in the container it runs in), so it must
    report failure in EVERY case - including when a reload call appears to
    succeed.
    """
    manager = NginxManager([])
    if not _redirect_shared_dir(tmp_path):
        pytest.skip("shared rules directory is not exposed as module state")

    monkeypatch.setattr(subprocess, "run", _fake_run(0))

    ok = await manager._deploy_via_file(_node(), "# rules\n")

    assert ok is False, (
        "a reload exit code of 0 was reported as successful activation. That code "
        "means only that the signal was delivered; it returns 0 for an invalid "
        "config too, so it cannot establish that rules are in force."
    )


@pytest.mark.asyncio
async def test_rule_file_is_still_written(tmp_path, monkeypatch):
    """
    The candidate must still be written, so a later reload (or an operator) can
    pick it up. The fix changes WHERE it lands and the reported OUTCOME, not the
    fact of the write.

    UPDATED for the Step 3 rebuild: the file is written to a unique temporary
    name and promoted to agent-<node>/rules.conf by rename, so a reader never
    sees a partial file and no leftovers remain in the rules directory.
    """
    manager = NginxManager([])
    if not _redirect_shared_dir(tmp_path):
        pytest.skip("shared rules directory is not exposed as module state")

    monkeypatch.setattr(subprocess, "run", _fake_run(1))

    await manager._deploy_via_file(_node(), "# staged rules\n")

    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written, "the rule file was not written at all"
    assert "staged rules" in written[0].read_text(encoding="utf-8")

    assert written[0].parent.name.startswith("agent-"), (
        "the candidate was not written into the per-node directory the vhost "
        f"includes, so it would never be loaded: {written[0]}"
    )


# -----------------------------------------------------------------------------
# Guard: the dead duplicated block after _ssh_deploy_sync() must stay deleted
# -----------------------------------------------------------------------------

def test_no_unreachable_code_after_ssh_deploy_sync():
    """
    `_ssh_deploy_sync` returned at what used to be line 624, yet a second copy of
    the upload block continued to line 689 with its own
    `logger.info("Successfully deployed configuration")` and `return True`.
    It was unreachable, and it made the function look as though it did the
    upload and reload twice. It must stay deleted.
    """
    src = inspect.getsource(NginxManager._ssh_deploy_sync)

    assert src.count("Successfully deployed configuration to") <= 1, (
        "a duplicated, unreachable deployment block is present in "
        "_ssh_deploy_sync - it was deleted in 0A.2 and must not come back"
    )


# -----------------------------------------------------------------------------
# A2 (review finding): restoring the file must RELOAD, so the running workers
# drop the unverified candidate. Pre-fix, _restore_previous_config restored the
# file on disk but never reloaded, so on the reload-success/verify-failure path
# the old workers kept enforcing a rejected rule.
# -----------------------------------------------------------------------------

def test_restore_previous_config_reloads_the_node():
    """
    Restoring the previous configuration must reload nginx afterwards.

    RED before the fix: _restore_previous_config renamed the backup back onto the
    live path and then returned, leaving nginx serving the (unverified) candidate
    it had already loaded. The fix calls _reload_nginx_with_validation after the
    restore, so on-disk state and serving state agree.
    """
    from unittest.mock import MagicMock

    manager = NginxManager([])
    node = _node()

    fake_sftp = MagicMock()
    fake_ssh = MagicMock()
    fake_ssh.open_sftp.return_value = fake_sftp

    manager._reload_nginx_with_validation = MagicMock(
        return_value={"success": True}
    )

    manager._restore_previous_config(
        fake_ssh,
        node,
        "/etc/nginx/waf-rules/agent-node_1/rules.conf",
        "/etc/nginx/waf-rules/agent-node_1/rules.conf.backup.1",
    )

    manager._reload_nginx_with_validation.assert_called_once_with(fake_ssh, node)


def test_dead_rollback_config_method_is_deleted():
    """
    `_rollback_config` was a wrong duplicate of `_restore_previous_config`: it did
    `sftp.rename(backup, current)` without removing `current` first, but paramiko's
    standard RENAME requires the target NOT to exist, so it would raise on a real
    rollback. It had zero callers. It must stay deleted.
    """
    assert not hasattr(NginxManager, "_rollback_config"), (
        "_rollback_config was a wrong duplicate of _restore_previous_config "
        "(rename-without-remove on a paramiko RENAME) with zero callers. Deleted "
        "2026-10-16; it must not come back."
    )
