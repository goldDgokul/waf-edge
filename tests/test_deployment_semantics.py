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
async def test_successful_reload_is_reported_as_success(tmp_path, monkeypatch):
    """The positive case must not be broken by the fix."""
    manager = NginxManager([])
    if not _redirect_shared_dir(tmp_path):
        pytest.skip("shared rules directory is not exposed as module state")

    monkeypatch.setattr(subprocess, "run", _fake_run(0))

    ok = await manager._deploy_via_file(_node(), "# rules\n")

    assert ok is True


@pytest.mark.asyncio
async def test_rule_file_is_still_written(tmp_path, monkeypatch):
    """
    The staged file must still be written, so a later reload (or an operator)
    can pick it up. The fix changes the reported OUTCOME, not the write.
    """
    manager = NginxManager([])
    if not _redirect_shared_dir(tmp_path):
        pytest.skip("shared rules directory is not exposed as module state")

    monkeypatch.setattr(subprocess, "run", _fake_run(1))

    await manager._deploy_via_file(_node(), "# staged rules\n")

    written = list(tmp_path.glob("dynamic-*.conf"))
    assert written, "the rule file was not written at all"
    assert "staged rules" in written[0].read_text(encoding="utf-8")


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
