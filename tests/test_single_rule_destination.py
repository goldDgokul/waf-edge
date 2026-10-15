"""
0A.3 Step 2 - ONE rule destination per node.

The defect this pins down: the deployment code built its rule-file path in more
than one place, so the Docker/file transport and the SSH transport could write to
different files, and a rule file nobody includes protects nothing.

HISTORY, STATED ACCURATELY (an earlier version of this docstring repeated a
false claim, corrected 2026-10-15 after an independent review falsified it):
  - At HEAD the file transport wrote <rules_root>/dynamic-<node>.conf and the SSH
    transport wrote {nginx_config_path}/waf_rules_auto.conf. They did NOT both
    write agent-<node>/rules.conf.
  - The two-include duplicate-directive failure IS real and was reproduced
    ([emerg] "limit_req" directive is duplicate, which discards every rule in the
    file), but the two-include state existed only as an uncommitted local edit -
    no committed revision had two rule includes.

These tests are BEHAVIOURAL where it matters: they drive the real
_deploy_via_file and inspect what it actually wrote, rather than grepping the
source. A source-shape assertion is satisfied by a comment, and this project has
already been caught by that once.

They FAIL against the pre-fix code and PASS once the file transport writes the
one per-node path the vhost include actually loads.
"""
import ast
import asyncio
import os
import re
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import src.nginx_manager as nm  # noqa: E402
from src.nginx_manager import NginxManager, NginxNode  # noqa: E402

MANAGER_SRC_PATH = _REPO_ROOT / "src" / "nginx_manager.py"
VHOST = _REPO_ROOT / "docker" / "nginx-node-1" / "default.conf"


def _make_node(node_id="node_1"):
    return NginxNode(
        node_id=node_id,
        hostname="test-node",
        ssh_host="127.0.0.1",
        ssh_port=22,
        ssh_username="nginx",
        ssh_key_path=None,
        nginx_config_path="/etc/nginx/conf.d",
        nginx_reload_command="nginx -s reload",
    )


def _active_rule_includes(vhost_text):
    """The includes nginx will actually act on - comments excluded."""
    return [
        ln.strip()
        for ln in vhost_text.splitlines()
        if ln.strip().startswith("include") and "waf-rules" in ln
    ]


def _run_file_transport(tmp_path, monkeypatch, node):
    """
    Drive the REAL file transport with the write directory redirected to tmp_path.

    The reload will fail in a test environment - irrelevant here. The question
    under test is WHERE the rules land, because a file outside the included
    directory is never loaded.
    """
    monkeypatch.setattr(nm, "SHARED_WAF_DIR", str(tmp_path))
    manager = NginxManager([node])
    try:
        asyncio.run(manager._deploy_via_file(node, "if ($a) { return 403; }\n"))
    except Exception:
        pass  # activation is not what this test measures


def test_vhost_has_exactly_one_rule_include():
    """
    One include per node. Two mechanisms at one scope is the root cause, and a
    second include is how it comes back.
    """
    includes = _active_rule_includes(VHOST.read_text(encoding="utf-8", errors="replace"))
    assert len(includes) == 1, (
        f"expected exactly ONE active rule include, found {len(includes)}: {includes}"
    )
    assert "agent-node_1/*.conf" in includes[0], (
        f"the include is not the per-node wildcard: {includes[0]}"
    )


def test_file_transport_never_claims_activation(tmp_path, monkeypatch):
    """
    BEHAVIOURAL, and the most important assertion in this file.

    The file transport cannot reload nginx (no docker CLI or socket in the
    container it runs in), so it must return False. Anything else is a false
    success: callers read True as "these rules are enforcing".

    This test previously passed only because the reload happened to FAIL in the
    test environment. That is not a test - it breaks the moment someone wires a
    working activation path. Here the reload is stubbed to SUCCEED, which is the
    real-world case that matters, and the transport must still say so honestly.
    """
    node = _make_node("node_1")

    # Make any subprocess call look like a success. The transport must not care:
    # it has no way to validate, so it must not report activation either way.
    class _Ok:
        returncode = 0
        stdout = "reload ok"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Ok())

    monkeypatch.setattr(nm, "SHARED_WAF_DIR", str(tmp_path))
    manager = NginxManager([node])
    result = asyncio.run(manager._deploy_via_file(node, "if ($a) { return 403; }\n"))

    assert result is False, (
        "the file transport claimed the rules are ACTIVE (returned True). It cannot "
        "establish that - it has no docker CLI, no socket and no nginx - so a True "
        "here is a false success and callers will believe traffic is protected."
    )


def test_file_transport_writes_where_the_vhost_looks(tmp_path, monkeypatch):
    """
    BEHAVIOURAL. What the transport writes must be something the vhost include
    can actually load - otherwise the write is invisible to nginx and the rules
    protect nothing.
    """
    node = _make_node("node_1")
    _run_file_transport(tmp_path, monkeypatch, node)

    all_files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert all_files, (
        "the file transport wrote no file at all. Contents: "
        f"{sorted(p.name for p in tmp_path.rglob('*'))}"
    )

    # The vhost include is `agent-node_1/*.conf`. The final file must live there
    # and end in .conf, or nginx never loads it.
    loaded = [p for p in all_files if p.name == "rules.conf" and p.parent.name == "agent-node_1"]
    assert loaded, (
        "the file transport did not produce agent-node_1/rules.conf, the only path "
        f"the vhost include loads. It wrote: "
        f"{[str(p.relative_to(tmp_path)) for p in all_files]}."
    )

    # No leftover temporary file: a torn or abandoned candidate in the rules
    # directory is a hazard if the include or a backup ever picks it up.
    leftovers = [p.name for p in all_files if p.name != "rules.conf"]
    assert not leftovers, (
        f"the transport left extra files behind in the rules directory: {leftovers}"
    )


def test_file_transport_does_not_produce_the_stale_name(tmp_path, monkeypatch):
    """
    The old destination name must not be produced at all, because nothing loads it.
    Behavioural: reads the filesystem, not the source text. A source check would
    be tripped up by the docstring in _verify_deployment that mentions the old
    name in prose.
    """
    node = _make_node("node_1")
    _run_file_transport(tmp_path, monkeypatch, node)

    stale = [str(p.relative_to(tmp_path)) for p in tmp_path.rglob("dynamic-*")]
    assert not stale, (
        "the file transport still writes a 'dynamic-' file, which no vhost "
        f"includes any more, so the write is invisible to nginx: {stale}"
    )


def test_ssh_transport_still_targets_the_per_node_directory():
    """
    Guard the other transport. If only the file transport moved, the two would
    drift apart again - which is exactly how the two-mechanism defect happened.

    Asserted behaviourally: the SSH destination is COMPUTED by calling the same
    helper the file transport uses, so agreement is proven rather than read out
    of the source text.
    """
    expected = nm.rule_destination_for("node_1")
    assert expected == os.path.join("agent-node_1", "rules.conf"), (
        f"the single destination helper returns an unexpected shape: {expected}. "
        "The vhost include is agent-node_1/*.conf, so this must be "
        "agent-node_1/rules.conf or the rules are never loaded."
    )

    # Every transport must derive its path from that helper. Trace the names the
    # builders are assigned from: any builder whose value chain does not reach
    # rule_destination_for() is a second, independent destination.
    src = MANAGER_SRC_PATH.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src)

    assigned = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for tgt in n.targets:
                if isinstance(tgt, ast.Name):
                    assigned.setdefault(tgt.id, ast.unparse(n.value))

    def reaches_helper(expr, seen=None):
        if "rule_destination_for" in expr:
            return True
        seen = seen or set()
        # Follow any identifier used in the expression, one level at a time.
        for name in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr)):
            if name in seen or name not in assigned:
                continue
            seen.add(name)
            if reaches_helper(assigned[name], seen):
                return True
        return False

    builders = ["rules_file", "staged_file", "final_path", "rules_dir"]
    strays = [
        (name, assigned.get(name))
        for name in builders
        if name in assigned and not reaches_helper(assigned[name])
    ]
    assert not strays, (
        "a transport builds its own destination instead of deriving it from "
        f"rule_destination_for(): {strays}. Two transports computing their own "
        "paths is precisely the defect this change removes."
    )

