"""
Behavioural tests for the deployment pipeline (plan item 0A.3).

WHY THIS FILE IS DIFFERENT FROM test_deploy_pipeline.py
    The previous test file asserted ORDERING: that the staging line appeared
    before the validation line in the source. It passed 100% while the validation
    step validated NOTHING, because the staged filename was not matched by nginx's
    include - so `nginx -t` only re-tested the current config.

    Checking the SHAPE of the code is not checking its BEHAVIOUR. These tests
    therefore drive a real candidate through a real nginx in a container, and
    assert on what nginx actually did.

FIXTURES COME FROM THE REAL CONFIG - NOT FROM A HAND-WRITTEN STAND-IN
    An earlier version of this file wrote its own miniature vhost and nginx.conf
    into a temp directory while claiming they "mirrored the real node". They did
    not: the real vhost is 53 non-comment lines in a single server block (41
    directive lines) and depends on the map blocks in basic.conf, while the
    stand-in had one include and no maps.

    A test that builds its own world can only make claims about that world. It
    cannot detect that the SHIPPING config drifted. So these fixtures:

      1. mount the repository's real docker/nginx-node-1/nginx.conf, default.conf
         and docker/shared/waf-rules/basic.conf at the paths nginx expects, and
      2. assert each mounted file's sha256 equals the RECORDED digest in
         EXPECTED_SHA256 below, so an edit to a vhost cannot silently pass
         unnoticed here.

    Only the agent rule file is supplied by the test, because that is the OUTPUT
    under test. It is placed beside a copy of the real basic.conf, because the
    real nginx.conf includes `/etc/nginx/waf-rules/basic.conf` literally and the
    vhost's `if ($has_sql_injection)` / `($has_xss)` / `($block_extension)` checks
    read the maps defined there - without it nginx refuses to load at all.

WHICH NODE
    Both edge nodes mount the same shared rules volume, and BOTH are covered here.
    Node 1 is where the behavioural tests run (its config is the one whose shape
    the generated rules must match). Node 2 is covered so that an edit to ITS
    vhost cannot pass silently either - the include shape is identical, and a
    change there is just as capable of breaking the pipeline.

TWO GROUPS OF TESTS, MARKED SO CI CAN SELECT THEM
    STRUCTURAL  (`structural`) - read files; need only Python. Not skipped, so
    they run everywhere including CI. They are the only thing that notices a vhost
    changing, or the old fixture creeping back.

    DOCKER      (`docker`) - drive a real nginx. Skipped when Docker is absent,
    because failing would make the suite unrunnable on a machine without Docker.
    A skip is honest as long as it is visible - `-rs` shows it.

    This split exists because of a real defect: the file previously carried NO
    marker at all, while CI runs `pytest -m "unit"` and `-m "integration"`. Both
    deselected every test in the file, so the drift tripwire existed and never ran
    anywhere except a developer's machine. A guarantee that holds only there is
    not a guarantee.
"""

import ast
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE1_DIR = REPO_ROOT / "docker" / "nginx-node-1"
NODE2_DIR = REPO_ROOT / "docker" / "nginx-node-2"
REAL_NGINX_CONF = NODE1_DIR / "nginx.conf"
REAL_VHOST = NODE1_DIR / "default.conf"
REAL_NODE2_NGINX_CONF = NODE2_DIR / "nginx.conf"
REAL_NODE2_VHOST = NODE2_DIR / "default.conf"
REAL_BASIC = REPO_ROOT / "docker" / "shared" / "waf-rules" / "basic.conf"

# RECORDED HASHES - the drift tripwire.
#
# A test that reads a file and compares it to itself can never detect an edit,
# because both sides of the comparison change together. That was the first
# version of the guard below, and it was worthless: removing a directive from the
# real vhost left every test in the file passing.
#
# Recording the digest from outside the file is what makes the change visible. If
# a vhost is edited, this test FAILS until the recorded hash is updated too - so a
# change to the shipping configuration can never happen silently. Updating the
# hash is the deliberate act of saying "yes, I meant to change the vhost", and it
# belongs in the same commit as the change.
#
# BOTH NODES. The first version recorded only node 1's files. Both nodes carry a
# per-node include into the SAME shared volume, so an edit to node 2 was just as
# capable of breaking the pipeline and passed silently.
EXPECTED_SHA256 = {
    REAL_NGINX_CONF: "366a4a02038f2d8e7cdb130ae109d0fbd0b5450392b6ad9718a2c8896d4473fb",
    REAL_VHOST: "f7d1f4c587997a2a463d8f46a6fb97a1b68cac49b4a299afdfca1a1d8180723d",
    REAL_NODE2_NGINX_CONF: "84c3cf298a4626e6e5fa2a4d731634b5fe28f61bc5c27ae826044305352e3358",
    REAL_NODE2_VHOST: "7ddb645e3aa4b40dc44ec1cb1e9bf77f43750866262cfe7eb51b050ea7f86ca6",
    REAL_BASIC: "2bbb037fa6ea42b34a1383e334cb7b7d3c7808f199642c25ca42a46784081924",
}

# A rules file containing an `if`, which is invalid at http scope and valid in
# server scope - the shape the generator actually emits.
IF_RULE = 'if ($request_uri ~ "(<script|onerror=)") { return 403; }\n'
RATE_RULE = "limit_req zone=waf_dynamic burst=5 nodelay;\n"

# The directive the generator emits, used as the POSITIVE CONTROL wherever a test
# asserts that something is ABSENT. An absence assertion against a tree that
# silently failed to load passes for no reason at all.
RATE_DIRECTIVE = "limit_req zone=waf_dynamic"

# A directive that exists nowhere in the project. The placeholder used previously
# was "limit_req zone=waf_disynamic" - a typo of the live directive. It happened to
# be absent, so the assertion held, but it was checking for a value that can never
# appear: it guarded nothing, and would have kept passing even if the real
# directive were misspelled throughout the shipped configuration.
NONEXISTENT_DIRECTIVE = "limit_req zone=zz_no_such_zone_zz"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except Exception:
        return False


DOCKER = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker is required for behavioural nginx tests",
)

# Selected by CI. `docker` needs Docker; `structural` does not and must always run.
docker = pytest.mark.docker
structural = pytest.mark.structural


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _tripwire_mismatches(expected_map: dict) -> list:
    """
    The drift check, as a function so a test can drive it with a rigged map.

    Returns a list of human-readable mismatches; empty means every guarded file
    still matches its recorded digest. Extracted from the test body specifically so
    that the guard-the-guard test can call the REAL comparison, rather than
    re-implementing an equivalent-looking expression that proves nothing.
    """
    mismatched = []
    for path, expected in expected_map.items():
        actual = _sha256(path)
        if actual != expected:
            mismatched.append(
                f"{Path(path).name}: expected {expected[:12]}... got {actual[:12]}..."
            )
    return mismatched


class _Tree:
    """
    A throwaway rules directory, mounted alongside the REAL nginx configuration.

    The configuration is not written by this class. It is the repository's own,
    mounted read-only at the paths nginx expects, and checked by hash so that a
    change to a vhost cannot make these tests pass against a stale idea of it.
    """

    # Where the real files must appear inside nginx:alpine.
    NGINX_CONF = "/etc/nginx/nginx.conf"
    VHOST = "/etc/nginx/conf.d/default.conf"
    RULES_ROOT = "/etc/nginx/waf-rules"
    CONTAINER = "nginx:alpine"

    def __init__(self, tmp_path: Path, node: int = 1):
        self.root = tmp_path
        self.node = node

        node_dir = NODE1_DIR if node == 1 else NODE2_DIR
        self.nginx_conf = node_dir / "nginx.conf"
        self.vhost = node_dir / "default.conf"

        # The real files must exist before we can mount them.
        for real in (self.nginx_conf, self.vhost, REAL_BASIC):
            assert real.is_file(), (
                f"the fixture mounts the repository's real configuration, but "
                f"{real} does not exist. These tests cannot stand in for it."
            )

        # The rules directory is the only thing this fixture owns. basic.conf is
        # copied in beside it because the real nginx.conf includes it by literal
        # path and the vhost's map-based checks depend on it.
        self.rules_root = self.root / "waf-rules"
        self.rules_dir = self.rules_root / f"agent-node_{node}"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REAL_BASIC, self.rules_root / "basic.conf")
        self.rules_file = self.rules_dir / "rules.conf"

    def write_rules(self, content: str):
        self.rules_file.write_text(content, encoding="utf-8")

    def remove_rules(self):
        if self.rules_file.exists():
            self.rules_file.unlink()

    def _run(self, args: str) -> str:
        # Real config mounted read-only; the temp dir holds only generated rules.
        proc = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{self.nginx_conf}:{self.NGINX_CONF}:ro",
                "-v", f"{self.vhost}:{self.VHOST}:ro",
                "-v", f"{self.rules_root}:{self.RULES_ROOT}:ro",
                self.CONTAINER,
                "sh", "-c", args,
            ],
            capture_output=True, text=True, timeout=120,
        )
        return (proc.stdout or "") + (proc.stderr or "")

    def nginx_t(self) -> str:
        return self._run("nginx -t")

    def loaded_config(self) -> str:
        return self._run("nginx -T")


class _FakeSSH:
    """
    A paramiko-shaped stand-in that answers every call _verify_deployment makes.

    WHY THIS IS NOT TRIVIAL, and why it replaced a simpler fake.

    The previous fake returned an object with no `.channel`. _verify_deployment's
    first statement is `stdout.channel.recv_exit_status()`, which then raised
    AttributeError. Its blanket `except Exception` caught that and returned
    success=False - so a test asserting only `result["success"] is False` PASSED
    for a reason with nothing to do with what it was checking. The section-scoped
    logic never ran; the test would have passed with that logic deleted outright.

    This fake supplies a channel whose recv_exit_status() returns a real code, so
    control reaches the logic under test. Tests using it assert on the SPECIFIC
    error text, which is what distinguishes "the section logic refused" from "the
    stand-in blew up".
    """

    class _Channel:
        def __init__(self, code: int):
            self._code = code

        def recv_exit_status(self):
            return self._code

    class _Out:
        def __init__(self, data: str, exit_code: int):
            self._data = data
            self.channel = _FakeSSH._Channel(exit_code)

        def read(self):
            return self._data.encode()

    def __init__(self, dump: str, exit_code: int = 0):
        self._dump = dump
        self._exit_code = exit_code

    def exec_command(self, cmd, timeout=None):
        return None, self._Out(self._dump, self._exit_code), self._Out("", 0)


def _node(node_id: str = "node_1"):
    from src.nginx_manager import NginxNode

    return NginxNode(
        node_id=node_id, hostname=node_id, ssh_host=node_id, ssh_port=22,
        ssh_username="root", ssh_key_path=None,
        nginx_config_path="/etc/nginx/conf.d", nginx_reload_command="nginx -s reload",
    )


# =============================================================================
# STRUCTURAL - no Docker. These run everywhere, including CI.
# =============================================================================

@structural
def test_fixture_mounts_the_repository_config_unchanged():
    """
    The drift tripwire, and the ONLY detector of an edit to a shipping vhost.

    It previously lived inside a module-wide skipif(Docker) and carried no marker,
    so in CI it was neither runnable nor selected. That is fixed by moving it out
    of the Docker group and marking it `structural`.

    Proof is by CONTENT as well as by digest. The digest alone would pass if the
    guard were pointed at the wrong file; the content check confirms that what is
    hashed is the configuration these tests actually mount.
    """
    assert EXPECTED_SHA256, "the tripwire guards no files at all"

    mismatched = _tripwire_mismatches(EXPECTED_SHA256)

    assert not mismatched, (
        "a configuration file the fixtures mount has changed. If that was "
        "deliberate, update EXPECTED_SHA256 in this file in the SAME commit - that "
        "is the point of the tripwire, so a change to the shipping configuration "
        "can never pass unnoticed:\n  " + "\n  ".join(mismatched)
    )

    # The guarded set must include the files the fixtures actually mount.
    for real in (REAL_NGINX_CONF, REAL_VHOST, REAL_NODE2_VHOST, REAL_BASIC):
        assert real in EXPECTED_SHA256, (
            f"{real.name} is mounted by these fixtures but is not on the tripwire, "
            f"so an edit to it would pass unnoticed"
        )


@structural
def test_tripwire_guards_both_nodes():
    """
    Guards the guard - honestly this time.

    The previous version of this test compared a live hash against a string of 64
    zeros. Two different digests are never equal, so the assertion could not fail
    whatever the files contained. It demonstrated that sha256 is not the constant
    function, which was never in doubt; it was theatre around a guard that genuinely
    worked, and it was reported as evidence that the guard worked. It is not
    evidence.

    This version drives the REAL comparison with a rigged map and requires the
    mismatch to be reported.
    """
    rigged = dict(EXPECTED_SHA256)
    rigged[REAL_VHOST] = "0" * 64

    reported = _tripwire_mismatches(rigged)

    assert reported, (
        "the tripwire did not notice a recorded digest that no file can match. It "
        "is incapable of detecting drift, so every assertion it guards is worthless."
    )
    assert REAL_VHOST.name in reported[0], (
        f"the tripwire reported a mismatch but not the file that was rigged: {reported}"
    )

    # The real map must be healthy, so the rigging above is the only failure
    # reported and this test cannot pass while the tripwire is genuinely broken.
    assert not _tripwire_mismatches(EXPECTED_SHA256), (
        "the recorded digests do not match the files on disk, so the tripwire is "
        "failing for real and the rigged comparison above proves nothing extra"
    )

    # BOTH NODES. Neither node's vhost could previously detect an edit to the other.
    guarded_dirs = {Path(p).parent.name for p in EXPECTED_SHA256}
    assert {"nginx-node-1", "nginx-node-2"} <= guarded_dirs, (
        f"the tripwire guards only {sorted(guarded_dirs)}; both nodes mount the "
        f"shared rules volume and both must be covered"
    )


@structural
def test_no_dead_stand_in_fixture_remains():
    """
    The rebuild must not leave the old stand-in behind, and the tests that notice
    a vhost changing must remain SELECTABLE BY CI.

    Two failures are checked here.

    1. DEAD CODE. An earlier revision built its own miniature configuration in a
    temp directory. When the fixtures were rebuilt to mount the real configuration,
    24 lines of that old class were left nested and unreachable in the middle of a
    test function - methods referencing `self` from no class at all, including a
    `_run` that mounted `{self.root}:/cfg:ro` and copied it into the container. Dead
    code that contradicts the file's own docstring is a trap for the next reader, and
    it is evidence the rebuild was done by patching rather than by rewriting.

    2. THE MARKERS. The tripwire never ran in CI because the file carried no marker
    while CI selects by marker. Marking it is only half the fix: the marks must be
    on the tests that need them. Asserted structurally rather than by trusting the
    decorators to stay put through future edits.
    """
    src = Path(__file__).read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src)

    # --- 1. dead code ------------------------------------------------------
    offenders = []

    def self_names_outside_classes(node):
        """
        Yield `self` Name nodes in this subtree that are NOT inside a class.

        A function may legitimately contain a nested class (a test-local
        stand-in). Descending into it would report that class's methods as
        offenders - a failure for the wrong reason, which is the exact class of
        mistake this file exists to stop making.
        """
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                continue  # its methods' `self` is legitimate
            if isinstance(child, ast.Name) and child.id == "self":
                yield child
            yield from self_names_outside_classes(child)

    def visit(node, class_stack):
        if isinstance(node, ast.ClassDef):
            class_stack.append(node.name)
            for child in ast.iter_child_nodes(node):
                visit(child, class_stack)
            class_stack.pop()
            return

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not class_stack and any(self_names_outside_classes(node)):
                offenders.append((node.name, node.lineno))

        for child in ast.iter_child_nodes(node):
            visit(child, class_stack)

    visit(tree, [])

    assert not offenders, (
        f"these functions use `self` but are not inside a class: {offenders}. They "
        f"are unreachable leftovers from the removed stand-in fixture. Delete them."
    )

    # --- 2. the markers ---------------------------------------------------
    def decorator_names(fn):
        return {
            d.id if isinstance(d, ast.Name)
            else getattr(d, "attr", None)
            for d in fn.decorator_list
        }

    functions = {
        n.name: n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    structural_tests = sorted(
        name for name, fn in functions.items()
        if name.startswith("test_") and "structural" in decorator_names(fn)
    )
    assert structural_tests, (
        "no test in this file is marked `structural`, so nothing here is selectable "
        "by a `-m structural` CI run and the drift tripwire is invisible again"
    )

    # Every test that guards the shipping configuration must be in that group.
    for name in ("test_fixture_mounts_the_repository_config_unchanged",
                 "test_tripwire_guards_both_nodes"):
        fn = functions.get(name)
        assert fn is not None, f"{name} has been removed; the drift guard is gone"
        assert not decorator_names(fn) & {"skipif"}, (
            f"{name} is skipped again - Docker or otherwise. It reads files and "
            f"needs nothing, and it is the only detector of a vhost change."
        )
        assert "structural" in decorator_names(fn), (
            f"{name} is no longer marked `structural`, so CI cannot select it"
        )

    # ...and the structural tests must not sit under a module-level Docker skip.
    # Checked through the AST, not by searching for the word "pytestmark" - a text
    # search matches this very assertion's own source and fails for no reason, which
    # is the same class of mistake as asserting against a value that cannot occur.
    module_marks = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "pytestmark":
                    module_marks.append(ast.unparse(node.value))

    docker_skips = [
        mark for mark in module_marks
        if "skipif" in mark and "docker" in mark.lower()
    ]
    assert not docker_skips, (
        f"a module-level skipif is applied to every test in this file: {docker_skips}. "
        f"The structural tests need no Docker, and while that mark is present they "
        f"skip whenever Docker is absent - which is what hid the tripwire from CI."
    )


# =============================================================================
# BEHAVIOURAL - real nginx in a container.
# =============================================================================

@docker
def test_the_fixture_is_the_real_configuration(tmp_path):
    """
    Proof is by CONTENT, not by name: every non-comment line of the repository's
    vhost must appear in what nginx actually loaded. If the fixture ever went back
    to writing its own miniature config, this fails - the stand-in had one include
    where the real vhost has 53 non-comment lines.
    """
    tree = _Tree(tmp_path)

    loaded = tree.loaded_config()

    # 1. The real nginx.conf's includes resolved, which means nginx really read the
    #    mounted file rather than a stand-in.
    assert "basic.conf" in loaded, (
        "the real nginx.conf includes waf-rules/basic.conf by literal path; that "
        "include did not resolve, so the fixture did not mount the real tree"
    )

    # 2. The maps from basic.conf are defined, so the vhost's checks can resolve.
    for map_var in ("has_sql_injection", "has_xss", "block_extension"):
        assert map_var in loaded, (
            f"the map '{map_var}' from basic.conf is absent from the loaded "
            f"configuration, so the vhost that uses it cannot be the real one"
        )

    # 3. CONTENT identity.
    real_vhost = REAL_VHOST.read_text(encoding="utf-8", errors="replace")
    real_lines = [
        ln.strip()
        for ln in real_vhost.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert len(real_lines) > 15, (
        f"the repository vhost has only {len(real_lines)} non-comment lines; this "
        f"does not look like the real configuration"
    )

    missing = [ln for ln in real_lines if ln not in loaded]
    assert not missing, (
        f"these lines are in the repository vhost but did NOT reach nginx, so the "
        f"fixture mounted something other than the real configuration: {missing[:5]}"
    )


@docker
def test_node2_vhost_mounts_and_loads(tmp_path):
    """
    Node 2 is covered too.

    Both nodes mount the shared rules volume with the same per-node include shape,
    so a change to node 2's vhost can break the pipeline exactly as one to node 1
    can - and the tripwire previously did not look at its files at all.
    """
    tree = _Tree(tmp_path, node=2)

    loaded = tree.loaded_config()

    assert "agent-node_2" in loaded, (
        "node 2's vhost does not include its own per-node rules directory; the "
        "include shape differs between the two nodes, so only one of them is "
        "actually covered by these fixtures"
    )

    real_lines = [
        ln.strip()
        for ln in REAL_NODE2_VHOST.read_text(encoding="utf-8", errors="replace").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    missing = [ln for ln in real_lines if ln not in loaded]
    assert not missing, (
        f"these lines are in node 2's repository vhost but did NOT reach nginx: "
        f"{missing[:5]}"
    )


@docker
def test_candidate_in_the_include_path_is_actually_parsed(tmp_path):
    """
    THE test that would have caught the original defect.

    A candidate containing `if` must be genuinely PARSED by `nginx -t` when it sits
    in the live include path. `if` is legal in server scope, so a correctly-placed
    candidate passes - the point is that nginx read it.

    The original defect was a candidate named so the include could not match it, in
    which case `nginx -t` never looks at it and reports success for the OLD config.
    To prove this test is not vacuous, the same rules are written under a name the
    include CANNOT match (see test_unmatched_candidate_is_not_validated).

    NOTE: `nginx -t` reports the *last* configuration it loaded, so a passing test
    alone does not prove our file was read. The assertions below therefore check the
    loaded contents, which is what distinguishes the two.
    """
    tree = _Tree(tmp_path)
    tree.write_rules(IF_RULE + RATE_RULE)

    out = tree.nginx_t()
    assert "test is successful" in out, (
        f"nginx rejected a candidate that is valid in server scope:\n{out}"
    )

    # The decisive assertion: the candidate was actually read.
    loaded = tree.loaded_config()
    assert "return 403;" in loaded, (
        "the candidate's directive is absent from the loaded configuration, so "
        f"`nginx -t` never validated it. Output:\n{loaded}"
    )


@docker
def test_unmatched_candidate_is_not_validated(tmp_path):
    """
    Documents the ORIGINAL defect, so the fix cannot silently regress.

    A file whose name the include cannot match is never parsed, and `nginx -t`
    then reports success for the OLD configuration while an unvalidated candidate
    sits on disk. This is exactly what the `.staged` naming did.

    The marker must be UNIQUE to the rule file. An earlier version of this test
    asserted that `return 403;` was absent from the loaded configuration - which can
    never hold against the real vhost, because its own
    `if ($has_sql_injection) { return 403; }` contains that text. It passed only
    against the hand-written stand-in, which had no such checks.
    """
    tree = _Tree(tmp_path)

    # A marker that appears nowhere else in the real configuration.
    marker = "ZZ-UNMATCHED-CANDIDATE-MARKER"
    candidate = f'if ($request_uri ~ "{marker}") {{ return 403; }}\n'

    # Write the candidate where the include will NOT match it.
    unmatched = tree.rules_dir / "rules.conf.staged"
    unmatched.write_text(candidate, encoding="utf-8")
    tree.remove_rules()  # no matching rules.conf

    loaded = tree.loaded_config()

    assert marker not in loaded, (
        f"precondition failed: the marker {marker} was loaded even though the "
        f"include cannot match a .staged file. Output:\n{loaded}"
    )
    # Positive control: the config loaded at all, so the absence above means what
    # it claims rather than being an empty dump.
    assert "return 403;" in loaded, (
        "sanity: the real vhost's own return 403 directives should be present, "
        "which is why the marker - not the directive text - is the assertion"
    )

    # And nginx still reports success, which is the trap: the validation step
    # would appear to pass while validating nothing.
    assert "test is successful" in tree.nginx_t(), (
        "nginx reported failure for an empty rules directory; the absent-file "
        "state is supposed to be valid"
    )


@docker
def test_absent_rules_file_is_a_valid_state(tmp_path):
    """
    Before the first deploy, and after a rollback, there is no rules file. nginx
    must still start - which is why the include is a wildcard over a directory.
    """
    tree = _Tree(tmp_path)
    tree.remove_rules()

    out = tree.nginx_t()
    assert "test is successful" in out, (
        f"nginx fails when the rules file is absent, so a first deploy or a "
        f"rollback would leave the node unable to start. Output:\n{out}"
    )


@docker
def test_per_node_directory_does_not_load_another_nodes_rules(tmp_path):
    """
    THE leak test. Both edge nodes mount the same host directory, so a wildcard
    over the SHARED root made node 1 load node 2's rules. Scoping the include to a
    per-node directory must prevent that.
    """
    tree = _Tree(tmp_path, node=1)

    # Node 2's rules, in node 2's own directory.
    other = tree.root / "waf-rules" / "agent-node_2"
    other.mkdir(parents=True, exist_ok=True)
    leak_marker = 'if ($request_uri ~ "/LEAK-MARKER") { return 403; }'
    (other / "rules.conf").write_text(leak_marker + "\n", encoding="utf-8")

    # Node 1 has no rules of its own.
    tree.remove_rules()

    loaded = tree.loaded_config()

    # Positive control FIRST: if node 1's include is absent from the dump, this
    # tree did not load what it claims to and the leak assertion proves nothing.
    assert "agent-node_1" in loaded, (
        "node 1's include did not appear in the loaded configuration at all, so "
        f"the leak assertion below cannot mean anything. Output:\n{loaded}"
    )
    assert "LEAK-MARKER" not in loaded, (
        "node 1 loaded node 2's rules; the shared directory leaks between nodes. "
        f"Output:\n{loaded}"
    )


@docker
def test_loaded_section_extraction_finds_our_file(tmp_path):
    """
    `nginx -T` labels each file. Verification relies on finding OUR file's section,
    because the same directive text can legitimately appear elsewhere in the loaded
    configuration - a match anywhere else would report a false success.
    """
    from src.nginx_manager import NginxManager

    tree = _Tree(tmp_path)
    tree.write_rules(RATE_RULE)
    loaded = tree.loaded_config()

    section = NginxManager._extract_loaded_section(
        loaded, f"{tree.RULES_ROOT}/agent-node_1/rules.conf"
    )

    assert section is not None, (
        f"our file's section was not found in the loaded config. Output:\n{loaded}"
    )
    assert RATE_DIRECTIVE in section, (
        "the extracted section does not contain our directive, so verification "
        "would match another file's identical line and report a false success"
    )


@docker
def test_same_directive_in_another_file_does_not_satisfy_verification(tmp_path):
    """
    Verification must not report success from a lookalike line in a DIFFERENT file,
    and must refuse for the RIGHT REASON.

    The rate-limit directive is not unique to the agent's rule file - any other
    included file could hold the same text. Verification therefore must confirm OUR
    file's section specifically.

    WHY THE ERROR TEXT IS ASSERTED. The previous version asserted only
    `result["success"] is False`. It passed because the fake SSH object raised
    AttributeError on `stdout.channel`, and _verify_deployment's blanket except
    turned that into failure - the section logic never executed. The test would
    have passed with that logic deleted. Asserting the specific message is what
    makes a pass here mean "the section check refused", not "something went wrong".
    """
    from src.nginx_manager import NginxManager

    tree = _Tree(tmp_path)

    # A second file, included by the real vhost's wildcard, holding the identical
    # directive. This is what a lookalike looks like.
    lookalike = tree.rules_dir / "000-other.conf"
    lookalike.write_text(RATE_RULE, encoding="utf-8")

    # Our own rules file does NOT exist.
    tree.remove_rules()
    loaded = tree.loaded_config()

    # Positive control: the lookalike's line really is in the loaded configuration,
    # so the refusal below is about SECTION SCOPE, not about an empty dump.
    assert RATE_DIRECTIVE in loaded, (
        "precondition: the identical line must be loaded from the lookalike file. "
        f"Output:\n{loaded}"
    )
    assert NONEXISTENT_DIRECTIVE not in loaded, (
        "the loaded configuration contains a directive that exists nowhere in the "
        "project, so these absence checks cannot be trusted"
    )

    result = NginxManager([])._verify_deployment(
        _FakeSSH(loaded), _node(), RATE_RULE
    )

    # It refused. `is False`, not merely falsy, so an exception cannot satisfy it.
    assert result["success"] is False, (
        "verification reported success although our own rules file does not exist; "
        "it matched an identical line from a different file. This is the "
        "false-success case the section-scoped check exists to prevent."
    )

    # ...and refused because our SECTION was missing.
    error = str(result.get("error", ""))
    assert "does not appear in the loaded configuration" in error, (
        f"verification refused, but not because our file's section was missing. Its "
        f"error was {error!r}. If that is an exception raised by the transport "
        f"stand-in, the section-scoped logic was never exercised and this test "
        f"proves nothing about it."
    )
    assert "agent-node_1" in error, (
        f"the refusal does not name the file it looked for: {error!r}"
    )


@docker
def test_verification_confirms_a_section_that_is_present(tmp_path):
    """
    The mirror of the test above, and the reason its refusal means something.

    A verifier that refuses everything is not verifying. With our own rules file
    present and loaded, the SAME code path must report success - otherwise the
    refusal above is indistinguishable from an inability to ever confirm.
    """
    from src.nginx_manager import NginxManager

    tree = _Tree(tmp_path)
    tree.write_rules(RATE_RULE)
    loaded = tree.loaded_config()

    result = NginxManager([])._verify_deployment(
        _FakeSSH(loaded), _node(), RATE_RULE
    )

    assert result["success"] is True, (
        f"verification refused a deployment whose rules ARE loaded (including its "
        f"section boundary), so it cannot distinguish a real deployment from a "
        f"missing one. Error: {result.get('error')!r}\nDump tail:\n{loaded[-2000:]}"
    )
