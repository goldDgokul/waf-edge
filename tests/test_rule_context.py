"""
Tests for the context-correctness of generated WAF rule configuration.

WHY THIS FILE EXISTS
    The critical defect: `WAFRule.to_nginx_config()` emits `if (...) { return 403; }`
    for the `block_url_pattern` and `block_user_agent` rule types. nginx permits
    `if` only inside a `server` or `location` block - not at `http` scope.

    The generated rule file was being included at `http` scope
    (docker/nginx-node-*/nginx.conf), so those two rule types were invalid where
    they were written. nginx refused to load them, which left the server unable to
    reload or restart - on a customer server, an outage.

    The fix is not to change the generator: all four rule types are valid inside a
    `server` block. The fix is to include the dynamic rule file at `server` scope.
    These tests lock that invariant in place.

    Note that no amount of text-matching validation would catch this defect - see
    NginxManager._validate_waf_rules, which only checks whether the words "deny",
    "return", "if" or "limit_req" appear. Only a real `nginx -t` run against the
    assembled configuration proves context validity.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_DIRS = [REPO_ROOT / "docker" / f"nginx-node-{n}" for n in (1, 2)]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _strip_comments(text: str) -> str:
    """Remove whole-line comments and blank lines so assertions see directives only."""
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kept.append(stripped)
    return "\n".join(kept)


def _http_block_directives(nginx_conf: str) -> str:
    """
    Return the text of the `http { ... }` block with nested `server`/`location`
    blocks removed, so that only directives sitting DIRECTLY at http scope remain.
    """
    start = nginx_conf.find("http {")
    assert start != -1, "nginx.conf has no http block"
    body = nginx_conf[start:]
    depth = 0
    out = []
    in_nested_block = False
    for line in body.splitlines():
        opener = line.count("{")
        closer = line.count("}")
        if not in_nested_block:
            if depth >= 1 and opener:
                in_nested_block = True
            else:
                out.append(line)
        depth += opener - closer
        if depth <= 1 and in_nested_block:
            in_nested_block = False
    return "\n".join(out)


# -----------------------------------------------------------------------------
# The invariant: dynamic rules must NOT be included at http scope
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("node_dir", NODE_DIRS, ids=lambda p: p.name)
def test_dynamic_rule_include_is_not_at_http_scope(node_dir):
    """
    RED before the fix: the dynamic rule file was included at http scope, where
    `if` is illegal, making two of the four rule types unloadable.
    """
    nginx_conf = _read(node_dir / "nginx.conf")
    http_scope = _http_block_directives(nginx_conf)

    offending = [
        line for line in http_scope.splitlines()
        if "include" in line and "dynamic-" in line
    ]
    assert not offending, (
        "dynamic rule file is included at http scope, where `if` is illegal "
        f"(two of four rule types become invalid): {offending}"
    )


# -----------------------------------------------------------------------------
# The invariant: dynamic rules MUST be included inside the server block
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("node_dir", NODE_DIRS, ids=lambda p: p.name)
def test_dynamic_rule_include_is_inside_server_block(node_dir):
    """
    The generated rule file must be included somewhere nginx allows `if`.

    UPDATED for 0A.3: the include is no longer a literal `dynamic-<node>.conf`.
    There is now exactly ONE rule include, and it is a wildcard over a per-node
    directory:
        include /etc/nginx/waf-rules/agent-node_1/*.conf;
    The invariant this test protects is unchanged - the include must be at SERVER
    scope, because generated rules contain `if` - but the shape it looks for is
    the single per-node wildcard, and there must be exactly one of them.
    """
    default_conf = _read(node_dir / "default.conf")
    directives = _strip_comments(default_conf)

    assert "server {" in directives, "default.conf has no server block"

    # Read the server block and take the includes inside it.
    body = directives.split("server {", 1)[1]
    rule_includes = [
        line.strip()
        for line in body.splitlines()
        if line.strip().startswith("include") and "waf-rules" in line
    ]

    assert rule_includes, (
        "default.conf includes no generated rule file inside its server block, so "
        "generated `if`-based rules have nowhere legal to be loaded"
    )
    assert len(rule_includes) == 1, (
        "there must be exactly ONE rule include per node. Two mechanisms at one "
        f"scope is what let the same batch land twice: {rule_includes}"
    )
    assert re.search(r"include\s+\S*agent-\S*\*\.conf\s*;", rule_includes[0]), (
        f"the single rule include is not the per-node wildcard: {rule_includes[0]}"
    )


# -----------------------------------------------------------------------------
# The invariant: basic.conf (maps) MUST stay at http scope
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("node_dir", NODE_DIRS, ids=lambda p: p.name)
def test_basic_conf_include_stays_at_http_scope(node_dir):
    """
    `map` is valid ONLY at http scope. The fix must not move basic.conf into the
    server block, or the maps would become invalid instead.
    """
    nginx_conf = _read(node_dir / "nginx.conf")
    http_scope = _http_block_directives(nginx_conf)

    assert any("basic.conf" in line and "include" in line
               for line in http_scope.splitlines()), (
        "basic.conf is no longer included at http scope; `map` is only valid "
        "there, so the static rules would break"
    )


# -----------------------------------------------------------------------------
# Guard: generated rate_limit rules must not reuse a vhost's own zones
# -----------------------------------------------------------------------------

def test_generator_rate_limit_rule_does_not_reuse_vhost_zone():
    """
    A generated dynamic rule file is included at server scope, at the same level
    as the vhost's own `limit_req`. Emitting `limit_req zone=main` - a zone the
    vhost already uses at that level - produces

        [emerg] "limit_req" directive is duplicate

    and nginx refuses to load the ENTIRE rule file, so every other rule in it is
    lost too. Generated rules must use a zone reserved for them.

    This was found live, not by unit test: the include had to be moved into the
    server block before nginx reported it.
    """
    gen = _read(REPO_ROOT / "src" / "waf_rule_generator.py")

    m = re.search(r'return f"limit_req zone=(\w+) burst=(\d+) nodelay;"', gen)
    assert m, "could not find the generated rate_limit rule"
    zone = m.group(1)

    assert zone != "main", (
        "generated rate_limit rule reuses zone=main, which every node vhost "
        "already applies at server scope - that is a duplicate directive and "
        "nginx will refuse to load the whole rule file"
    )


@pytest.mark.parametrize("node_dir", NODE_DIRS, ids=lambda p: p.name)
def test_node_defines_the_zone_generated_rules_use(node_dir):
    """
    Whatever zone the generator emits must actually be declared in the node's
    http block, or nginx fails with `unknown limit_req_zone`.
    """
    gen = _read(REPO_ROOT / "src" / "waf_rule_generator.py")
    m = re.search(r'return f"limit_req zone=(\w+) burst=', gen)
    assert m
    zone = m.group(1)

    nginx_conf = _read(node_dir / "nginx.conf")
    assert f"zone={zone}:" in nginx_conf, (
        f"generated rules use zone={zone} but {node_dir.name}/nginx.conf does "
        f"not declare it"
    )


# -----------------------------------------------------------------------------
# Guard: the generator's `if` output is only ever legal at server/location scope
# -----------------------------------------------------------------------------

def test_generator_if_rules_are_the_reason_for_server_scope():
    """
    Documents WHY the include belongs at server scope: the generator emits `if`
    for two rule types. If this ever changes, the scope requirement should be
    revisited deliberately rather than by accident.
    """
    gen = _read(REPO_ROOT / "src" / "waf_rule_generator.py")

    assert 'if ($request_uri ~' in gen, "expected an `if`-based url pattern rule"
    assert 'if ($http_user_agent ~' in gen, "expected an `if`-based user agent rule"

    # Every rule type the generator emits, and the directive it produces.
    # `deny` and `limit_req` are also legal at http scope; `if` is not.
    for rule_type in ("block_ip", "block_url_pattern", "block_user_agent", "rate_limit"):
        assert rule_type in gen, f"rule type {rule_type} disappeared from the generator"
