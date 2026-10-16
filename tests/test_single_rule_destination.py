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

import pytest

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
    BEHAVIOURAL, AND ITS CLAIM WAS REVERSED ON 2026-10-16.

    WHAT IT USED TO ASSERT, and why that was a defect in the test rather than a
    property of the code: it required the file transport to produce
    `agent-node_1/rules.conf` - i.e. it demanded that the transport write its output
    into the directory the vhost includes, and treated that as the passing
    condition. But the transport performs NO validation, so satisfying this test
    meant parking an unvalidated file exactly where nginx would load it on the next
    legitimate reload. That is the original outage class this workstream exists to
    prevent (`[emerg] "if" directive is not allowed here in dynamic-node_1.conf:9`).

    The test was therefore guarding the bug. It passed against the broken code and
    would have failed against the fix - the clearest possible sign that its
    assertion encoded the defect.

    WHAT IT ASSERTS NOW: the candidate lands SOMEWHERE under the rules root (so the
    work is not lost), and NOT at any path the include can match (so an unvalidated
    directive cannot reach a running nginx). Both halves matter: a transport that
    wrote nothing at all would pass the second half while being useless.
    """
    node = _make_node("node_1")
    _run_file_transport(tmp_path, monkeypatch, node)

    all_files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert all_files, (
        "the file transport wrote no file at all. Contents: "
        f"{sorted(p.name for p in tmp_path.rglob('*'))}"
    )

    # HALF 1 - something was staged. The candidate must not simply vanish.
    assert any(p.name == "rules.conf.pending" for p in all_files), (
        "the transport wrote no staged candidate. It wrote: "
        f"{[str(p.relative_to(tmp_path)) for p in all_files]}."
    )

    # HALF 2 - THE SAFETY PROPERTY. Nothing matching the vhost include
    # `agent-<node>/*.conf` may exist, because nothing here has been validated.
    # Written as a real glob rather than a name comparison, so it fails if someone
    # later stages into a differently-named file that the glob still catches.
    include_matches = sorted(
        str(p.relative_to(tmp_path)) for p in tmp_path.rglob("agent-node_1/*.conf")
    )
    assert include_matches == [], (
        "the file transport placed an UNVALIDATED candidate where the vhost include "
        f"loads it: {include_matches}. This transport runs no `nginx -t`, so a file "
        "there is loaded by the next legitimate reload and can take the node down - "
        "the exact failure this workstream exists to prevent."
    )

    # HALF 3 - no torn leftovers from the tmp+rename dance.
    leftovers = [
        p.name for p in all_files
        if p.name not in ("rules.conf.pending", "rules.conf")
    ]
    assert not leftovers, (
        f"the transport left a torn or abandoned temporary file behind: {leftovers}"
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


HELPER_NAMES = {
    "rule_destination_for",
    "remote_rule_destination",
    # Added 2026-10-16 with the staging change. The file transport now derives its
    # STAGED path from its own helper, and the guard must model that helper or it
    # reports the new, correct code as a stray. Adding a name here is a statement
    # that the helper is part of the sanctioned destination chain - not a way to
    # silence the guard.
    "staging_destination_for",
}
GUARDED_NAMES = ("rules_file", "staged_file", "final_path", "rules_dir", "our_file")


def destination_strays(source: str) -> list:
    """
    Return every assignment to a guarded destination name that does NOT derive from
    the destination helpers.

    Extracted from the test body so the guard can be driven with SYNTHETIC sources.
    A guard that is only ever run against the real file cannot be shown to catch the
    thing it was written for - and this guard was written for a pattern that had
    already slipped through it once.
    """
    tree = ast.parse(source)

    def called_helper(node) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = sub.func
                name = (
                    fn.id if isinstance(fn, ast.Name)
                    else fn.attr if isinstance(fn, ast.Attribute)
                    else None
                )
                if name in HELPER_NAMES:
                    return True
        return False

    assignments = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for tgt in targets:
                if isinstance(tgt, ast.Name):
                    assignments.setdefault(tgt.id, []).append(n.value)

    def reaches_helper(node, seen=None) -> bool:
        # A BARE ANNOTATION HAS NO VALUE, and this recursion must not assume one.
        #
        # Measured 2026-10-16: with `staged_file` newly guarded, the guard CRASHED
        # with `AttributeError: 'NoneType' object has no attribute '_fields'`. The
        # cause was not the new code but a latent bug here: the recursion follows
        # every name mentioned in a guarded expression, reached the dataclass field
        # declaration `node_id: str` (an AnnAssign whose .value is None), and called
        # ast.walk(None). The guard had been passing only because the names it
        # happened to traverse had values.
        #
        # A guard that crashes is a guard that is not running, so this is fixed
        # rather than worked around: a declaration is skipped, and the guard's
        # verdict is computed only from real assignments.
        if node is None:
            return False
        if called_helper(node):
            return True
        seen = seen or set()
        for name in {x.id for x in ast.walk(node) if isinstance(x, ast.Name)}:
            if name in seen or name not in assignments:
                continue
            seen.add(name)
            if all(reaches_helper(v, seen) for v in assignments[name]):
                return True
        return False

    strays = []
    for name in GUARDED_NAMES:
        for value in assignments.get(name, []):
            if not reaches_helper(value):
                strays.append((name, ast.unparse(value)))
    return strays


def test_ssh_transport_still_targets_the_per_node_directory():
    """
    Guard the other transport. If only the file transport moved, the two would
    drift apart again - which is exactly how the two-mechanism defect happened.

    Asserted behaviourally: the SSH destination is COMPUTED by calling the same
    helper the file transport uses, so agreement is proven rather than read out
    of the source text.

    The static half of this test is a REGRESSION tripwire over the source, and its
    limits are stated plainly: it recognises derivation by following assignments, so
    it cannot see a path built through a function call it does not model. The
    behavioural tests are what actually constrain the transports.
    """
    expected = nm.rule_destination_for("node_1")
    assert expected == os.path.join("agent-node_1", "rules.conf"), (
        f"the single destination helper returns an unexpected shape: {expected}. "
        "The vhost include is agent-node_1/*.conf, so this must be "
        "agent-node_1/rules.conf or the rules are never loaded."
    )

    src = MANAGER_SRC_PATH.read_text(encoding="utf-8", errors="replace")
    strays = destination_strays(src)

    assert not strays, (
        "a part of the deployment code assigns a destination that does not derive "
        f"from the helpers: {strays}. EVERY assignment must derive, because a later "
        "assignment overwrites the earlier one - and a hardcoded value that happens "
        "to match today is still a second definition of where rules live, which is "
        "the defect this change removes."
    )

    # Every transport must derive its path from that helper - see
    # test_the_destination_guard_catches_the_patterns_it_was_written_for below,
    # which drives destination_strays() with synthetic sources. This test only
    # asserts the real file is clean.


def test_the_destination_guard_catches_the_patterns_it_was_written_for():
    """
    Drive the guard with the evasions it must catch.

    A guard only ever run against the real file cannot be shown to catch anything.
    That is not a hypothetical here: this guard was reported as closing the
    helper-then-overwrite pattern, and an independent review falsified it by
    re-adding exactly that pattern to src/nginx_manager.py and watching this file
    still pass. The quantifier was `any` over the assignment list, so a later
    hardcode was collected and then ignored.

    Each case below is a shape that has either occurred in this code or was used to
    defeat a previous version of the guard.
    """
    good = """
rules_file = os.path.join(SHARED_WAF_DIR, rule_destination_for(node.node_id))
"""
    assert not destination_strays(good), "a correct derivation was flagged"

    # THE FALSIFYING CASE. Python is last-writer-wins, so the second line is the
    # destination. This must be flagged.
    overwrite = """
rules_file = os.path.join(SHARED_WAF_DIR, rule_destination_for(node.node_id))
rules_file = os.path.join(SHARED_WAF_DIR, "dynamic-hardcoded.conf")
"""
    assert destination_strays(overwrite), (
        "the helper-then-overwrite pattern was NOT flagged. This is the exact shape "
        "an independent review used to falsify the previous version of this guard, "
        "and it deploys to a file no include matches while reporting success."
    )

    # A hardcode that HAPPENS to equal the helper's output today. It cannot be
    # distinguished from the real thing by its value, and it is still a second
    # definition - which is the drift this file exists to prevent.
    plausible = """
rules_file = os.path.join(SHARED_WAF_DIR, "agent-node_1", "rules.conf")
"""
    assert destination_strays(plausible), (
        "a hardcoded destination that happens to match today was accepted; the "
        "second definition of where rules live is the defect, not the value"
    )

    # An unrelated name that merely CONTAINS the helper's name must not satisfy it.
    name_lookalike = """
rules_file = build_rule_destination_for(node.node_id)
"""
    assert destination_strays(name_lookalike), (
        "a different function whose name contains the helper's was accepted"
    )

    # A plain hardcode, the original defect.
    hardcoded = """
our_file = f"/etc/nginx/waf-rules/agent-{node.node_id}/rules.conf"
"""
    assert destination_strays(hardcoded), "a hardcoded f-string was accepted"

    # Assignment THROUGH another name that derives is fine.
    via_local = """
final_path = f"{REMOTE_WAF_RULES_DIR}/{remote_rule_destination(node.node_id)}"
rules_dir = final_path.rsplit('/', 1)[0]
"""
    assert not destination_strays(via_local), (
        "a value derived through another guarded name was flagged; derivation "
        "through the chain is legitimate"
    )

    # But if ANY link in that chain is a hardcode, the chain is broken.
    broken_chain = """
final_path = f"{REMOTE_WAF_RULES_DIR}/{remote_rule_destination(node.node_id)}"
rules_dir = "/etc/nginx/waf-rules/agent-node_1"
"""
    assert destination_strays(broken_chain), (
        "a chain with a hardcoded link was accepted"
    )


def test_node_id_is_validated_before_it_becomes_a_directory():
    """
    node_id becomes a DIRECTORY NAME, so an id that cannot appear in the vhost's
    include path produces a rule file nginx never reads - deployment reports success
    while protecting nothing.

    WHY THIS TEST EXISTS SEPARATELY. validate_node_id was added to close that hole,
    and an independent review showed the fix had ZERO coverage: deleting the call
    from rule_destination_for left every test in the repository passing, and the
    whole suite passed against a source tree that did not contain the function at
    all. A fix nobody tests is a fix that gets removed by the next refactor.
    """
    good = ["node_1", "node_2", "node-1", "node.2", "Node_3", "nginx-local", "a" * 64]
    for node_id in good:
        assert nm.validate_node_id(node_id) == node_id, (
            f"a legitimate node id was rejected: {node_id!r}"
        )
        # ...and it must actually reach a path the include can match.
        assert nm.rule_destination_for(node_id).endswith("rules.conf")

    bad = [
        "node/1",          # path separator - becomes a nested directory
        "node\\1",          # windows separator
        "../evil",         # traversal
        "..",              # traversal
        ".",               # the rules root itself
        "",                # empty
        " ",               # whitespace only
        "-node",           # leading hyphen (glob/regex-hostile)
        "_node",           # leading underscore
        "node 1",          # space
        "node\t1",         # tab
        "node_1\n",        # TRAILING NEWLINE - accepted by re.match with '$'
        "\nnode_1",        # leading newline
        "node_1\r",        # carriage return
        "node*",           # glob metacharacter - would match other nodes' files
        "node?",
        "node[1]",         # character class
        "nоde_1",          # unicode lookalike (Cyrillic o)
        "a" * 65,          # over length
    ]
    for node_id in bad:
        with pytest.raises(ValueError):
            nm.validate_node_id(node_id)

    # The newline case is called out because it is the one that slipped through:
    # the pattern used re.match with a '$' anchor, and '$' matches before a trailing
    # newline, so 'node_1\n' was accepted and produced
    # 'agent-node_1\n/rules.conf' - a directory no include can match.
    with pytest.raises(ValueError):
        nm.rule_destination_for("node_1\n")

    # And the guard must be wired in, not merely defined. This is the assertion that
    # fails if someone deletes the call while leaving the function.
    with pytest.raises(ValueError):
        nm.rule_destination_for("../evil")



# ============================================================================
# STAGING (0A.1(c)) - added 2026-10-16
#
# The file transport used to place an UNVALIDATED candidate at agent-<node>/
# rules.conf, the exact path the vhost includes. It reported failure honestly, but
# the file still became enforcing policy at the node's next legitimate reload. These
# tests pin the corrected contract: unvalidated work is staged somewhere no include
# can reach, and the live path is only for content that has passed a real nginx test.
#
# Each test below is written so that it FAILS against the pre-fix code. That is the
# point of writing them at all: a test that passes before and after proves nothing.
# ============================================================================


def test_staging_path_can_never_be_matched_by_an_include():
    """
    The safety property, asserted on the helper itself rather than on a write.

    Two ways staging could regress into danger, both checked:
      (a) it stops being under a directory of its own (someone stages into
          agent-<node>/ and relies on the extension);
      (b) its filename ends in .conf, so an include wildcard or a future literal
          include would pick it up.
    """
    staged = nm.staging_destination_for("node_1")

    assert staged != nm.rule_destination_for("node_1"), (
        "the staging path and the live path are the same, so an unvalidated "
        "candidate is written where nginx loads it - the defect 0A.1(c) removed"
    )

    # (b) - the basename must not look like an nginx config file.
    basename = staged.replace("\\", "/").rsplit("/", 1)[-1]
    assert not basename.endswith(".conf"), (
        f"the staged candidate is named {basename!r}, which ends in .conf, so any "
        f"include glob the vhost grows later could load an unvalidated file"
    )

    # (a) - it must not sit inside the per-node include directory. Asserted with a
    # real glob over a real directory, not by string comparison, so the test fails
    # if the layout changes underneath it.
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / staged
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("if ($a) { return 403; }\n", encoding="utf-8")

        matched = sorted(
            str(p.relative_to(td)) for p in Path(td).rglob("agent-node_1/*.conf")
        )
        assert matched == [], (
            f"a staged candidate landed where the vhost include loads it: {matched}"
        )


def test_node_id_validation_still_runs_on_the_staging_path():
    """
    Moving the write must not move it out from under validation.

    A traversal id would escape the rules root in EITHER direction, so the check has
    to be on the path actually used. This fails if someone later builds the staging
    path by string concatenation instead of calling the helper.
    """
    for bad in ["../evil", "node/1", "node_1\n"]:
        with pytest.raises(ValueError):
            nm.staging_destination_for(bad)


def test_staging_guard_is_wired_into_the_file_transport(tmp_path, monkeypatch):
    """
    The guard must be CALLED, not merely defined.

    Deletes nothing - it drives the real transport and then asserts the live path is
    empty while the staging path is not. This is the behavioural form: a defined-but
    -unused helper would leave the live path populated and fail here.
    """
    node = _make_node("node_1")
    _run_file_transport(tmp_path, monkeypatch, node)

    live = list(tmp_path.rglob("agent-node_1/*.conf"))
    staged = [p for p in tmp_path.rglob("*") if p.is_file() and p.name.endswith(".pending")]

    assert staged, (
        "the transport staged nothing at all. If _deploy_via_file stopped calling "
        "staging_destination_for(), the candidate would go to the live path instead "
        "and this assertion is what notices."
    )
    assert live == [], (
        f"the transport wrote to the include-matched live path: "
        f"{[str(p.relative_to(tmp_path)) for p in live]}"
    )


def test_file_transport_still_reports_failure_while_staging(tmp_path, monkeypatch):
    """
    Staging is not activation, and the report must keep saying so.

    Guarding the honest half too: a change that made the transport return True
    because 'the file is written' would be the false-success defect again, just
    relocated.
    """
    node = _make_node("node_1")
    monkeypatch.setattr(nm, "SHARED_WAF_DIR", str(tmp_path))
    manager = NginxManager([node])
    result = asyncio.run(manager._deploy_via_file(node, "if ($a) { return 403; }\n"))
    assert result is False, (
        "the file transport claimed success. It cannot validate or reload nginx, so "
        "there is no state it could have established that would justify True."
    )


def test_staging_sweep_removes_only_stale_candidates(tmp_path, monkeypatch):
    """
    The staging directory must not grow forever, and the sweep must be unable to
    do harm.

    Added 2026-10-16 after an independent review pointed out that the staging path
    is one FIXED filename per node on a SHARED volume, so without housekeeping it
    accumulates, and a stale candidate is its own hazard (a later promotion step, or
    an operator copying "the staged file", could pick up a candidate from days ago).

    Paired assertions on purpose: a sweeper that deletes everything passes half of
    this and would be worse than none.
    """
    import time as _time

    monkeypatch.setattr(nm, "SHARED_WAF_DIR", str(tmp_path))

    stale = tmp_path / "_staging" / "agent-node_1" / "rules.conf.pending"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("# from days ago\n", encoding="utf-8")
    aged = _time.time() - (48 * 60 * 60)
    os.utime(stale, (aged, aged))

    fresh = tmp_path / "_staging" / "agent-node_2" / "rules.conf.pending"
    fresh.parent.mkdir(parents=True, exist_ok=True)
    fresh.write_text("# just now\n", encoding="utf-8")

    live = tmp_path / "agent-node_1" / "rules.conf"
    live.parent.mkdir(parents=True, exist_ok=True)
    live.write_text("# THE LIVE RULES\n", encoding="utf-8")

    removed = nm.sweep_stale_staged_candidates()

    assert removed >= 1 and not stale.exists(), "the stale candidate was not swept"
    assert fresh.exists(), "the sweep deleted a FRESH candidate it should have kept"
    assert live.exists() and "LIVE" in live.read_text(encoding="utf-8"), (
        "the sweep touched the live rules path - it must only ever touch _staging/"
    )


def test_staging_sweep_cannot_be_broken_by_a_hostile_entry(tmp_path, monkeypatch):
    """
    Housekeeping must never be able to fail a deployment.

    A directory sitting where a file is expected forces the OSError path; the sweep
    must absorb it and return a count, not raise.
    """
    monkeypatch.setattr(nm, "SHARED_WAF_DIR", str(tmp_path))
    hostile = tmp_path / "_staging" / "agent-node_1" / "dir-not-file"
    hostile.mkdir(parents=True, exist_ok=True)

    result = nm.sweep_stale_staged_candidates()
    assert isinstance(result, int), "the sweep raised instead of returning a count"


def test_deploy_path_calls_the_staging_sweep(tmp_path, monkeypatch):
    """
    The sweep must be WIRED IN, not merely defined.

    An unrelated stale candidate is planted elsewhere in the tree; driving the real
    transport must remove it. This fails if someone deletes the sweep call from
    _deploy_via_file while leaving the function in place - the same
    defined-but-unused defect the reviewer flagged as this project's recurring
    pattern.
    """
    import time as _time

    monkeypatch.setattr(nm, "SHARED_WAF_DIR", str(tmp_path))
    stale_elsewhere = tmp_path / "_staging" / "agent-old" / "rules.conf.pending"
    stale_elsewhere.parent.mkdir(parents=True, exist_ok=True)
    stale_elsewhere.write_text("# forgotten\n", encoding="utf-8")
    aged = _time.time() - (48 * 60 * 60)
    os.utime(stale_elsewhere, (aged, aged))

    node = _make_node("node_1")
    manager = NginxManager([node])
    asyncio.run(manager._deploy_via_file(node, "if ($a) { return 403; }\n"))

    assert not stale_elsewhere.exists(), (
        "a deploy did not sweep the staging tree, so the sweep call is missing from "
        "_deploy_via_file - housekeeping that is never called is not housekeeping"
    )
