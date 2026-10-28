"""0B.6: tenant/policy readiness (exclusions, sensitivity, quotas).

Plan v7.5 0B.6: "Design rule exclusions, sensitivity and quotas so they
can become tenant-scoped later; do not create another global-only rule
model that Phase 2 must replace."

Design decision (ADR 0003): tenant policy lives in per-tenant policy
objects rendered to per-tenant ModSecurity rules files that are attached
at server scope via `modsecurity_rules_file` - the connector's native
per-vhost hook. Nothing in the model is global-only: a tenant's
sensitivity, exclusions and rate limit render into THAT tenant's file,
and additional tenants are additive files, not a shared dump.

The unit tests pin the model's validation and rendering on fabricated
policies; the docker test proves the rendered tenant file actually loads
in the shipped node image (nginx -t through the node's entrypoint).
"""

import json
import re
from pathlib import Path

import pytest

from src.tenant_policy import (
    RateLimit,
    RuleExclusion,
    TenantPolicy,
    load_policies,
    render_rules_file,
    render_tenant_vhost,
    render_vhost_snippet,
    render_vhosts_file,
    validate_policies,
    POLICIES_SOURCE,
    GENERATED_DIR,
    NODE_MAX_BODY_SIZE,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _policy(**overrides):
    defaults = dict(
        tenant_id="acme", hostname="acme.example.com",
        sensitivity=1, exclusions=(), rate_limit=None,
    )
    defaults.update(overrides)
    return TenantPolicy(**defaults)


class TestValidation:
    def test_rejects_bad_sensitivity(self):
        with pytest.raises(ValueError):
            _policy(sensitivity=5)

    def test_rejects_zero_sensitivity(self):
        with pytest.raises(ValueError):
            _policy(sensitivity=0)

    def test_rejects_empty_tenant_id(self):
        with pytest.raises(ValueError):
            _policy(tenant_id="")

    def test_rejects_non_numeric_rule_id(self):
        with pytest.raises(ValueError):
            RuleExclusion(rule_id="9421x0")

    def test_rejects_negative_rate(self):
        with pytest.raises(ValueError):
            RateLimit(rate=0)

    def test_rejects_negative_burst(self):
        with pytest.raises(ValueError):
            RateLimit(rate=10, burst=-1)

    def test_duplicate_tenant_ids_rejected(self):
        with pytest.raises(ValueError):
            validate_policies([_policy(), _policy()])

    def test_duplicate_hostnames_rejected(self):
        with pytest.raises(ValueError):
            validate_policies([_policy(), _policy(hostname="other")])

    def test_valid_policies_pass(self):
        validate_policies([_policy(), _policy(tenant_id="other", hostname="o.example.com")])


class TestRenderRulesFile:
    def test_sensitivity_renders_paranoia_level(self):
        text = render_rules_file(_policy(sensitivity=2))
        assert 'setvar:tx.paranoia_level=2' in text

    def test_exclusion_renders_rule_removal(self):
        text = render_rules_file(_policy(exclusions=(RuleExclusion("942100"),)))
        assert "SecRuleRemoveById 942100" in text

    def test_path_scoped_exclusion_uses_ctl(self):
        text = render_rules_file(_policy(
            exclusions=(RuleExclusion("942100", path_prefix="/api/status"),)))
        assert "ctl:ruleRemoveById=942100" in text
        assert "@beginsWith /api/status" in text

    def test_tenant_scoped_not_global_dump(self):
        """One tenant's file contains only that tenant's directives."""
        acme = render_rules_file(_policy(exclusions=(RuleExclusion("942100"),)))
        other = render_rules_file(_policy(tenant_id="other", hostname="o.example.com"))
        assert "other" not in acme
        assert "942100" not in other

    def test_rendering_is_deterministic(self):
        a = render_rules_file(_policy(exclusions=(RuleExclusion("942100"), RuleExclusion("930120"))))
        b = render_rules_file(_policy(exclusions=(RuleExclusion("942100"), RuleExclusion("930120"))))
        assert a == b

    def test_ctl_rule_ids_unique_per_exclusion(self):
        text = render_rules_file(_policy(exclusions=(
            RuleExclusion("942100", path_prefix="/a"),
            RuleExclusion("942100", path_prefix="/b"),
        )))
        ids = [line for line in text.splitlines() if "ctl:ruleRemoveById" in line]
        assert len({re.search(r'id:(\d+)', line).group(1) for line in ids}) == len(ids)


class TestVhostSnippet:
    def test_attaches_tenant_rules_file(self):
        snippet = render_vhost_snippet(_policy())
        assert "modsecurity_rules_file" in snippet
        assert "acme.rules" in snippet

    def test_rate_limit_renders_zone(self):
        snippet = render_vhost_snippet(_policy(rate_limit=RateLimit(rate=5, burst=10)))
        assert "limit_req zone=tenant-acme" in snippet
        assert "burst=10" in snippet

    def test_no_rate_limit_no_limit_req(self):
        snippet = render_vhost_snippet(_policy())
        assert "limit_req" not in snippet


class TestCheckedInArtifacts:
    """The checked-in policy source and generated files are consistent."""

    def test_policy_source_exists_and_loads(self):
        policies = load_policies(POLICIES_SOURCE)
        assert len(policies) >= 2
        validate_policies(policies)

    def test_generated_files_match_rendered_policies(self):
        policies = load_policies(POLICIES_SOURCE)
        for policy in policies:
            generated = GENERATED_DIR / f"{policy.tenant_id}.rules"
            assert generated.read_text(encoding="utf-8") == render_rules_file(policy), (
                f"{generated} is stale; regenerate it from {POLICIES_SOURCE.name}"
            )


class TestTenantProxyPolicy:
    """0C.1-0C.4 / 0D.1: a tenant with an origin renders a FULL proxy vhost;
    a tenant without an origin renders none (demo tenants keep their canned
    vhosts from waf-node.conf - no duplicate server_name)."""

    def _proxy_policy(self, **overrides):
        defaults = dict(
            tenant_id="acme", hostname="acme.edge.test",
            origin_url="http://test-origin:8090", max_body_size="1m",
        )
        defaults.update(overrides)
        return _policy(**defaults)

    def test_no_origin_renders_no_vhost(self):
        assert render_tenant_vhost(_policy()) == ""

    def test_proxy_vhost_renders_origin_and_identity(self):
        text = render_tenant_vhost(self._proxy_policy())
        assert "server_name acme.edge.test;" in text
        assert "set $origin_upstream http://test-origin:8090;" in text
        assert "proxy_pass $origin_upstream;" in text
        assert "resolver 127.0.0.11" in text
        # 0C.1 trust policy: the edge OVERWRITES client-supplied XFF
        assert "proxy_set_header X-Forwarded-For $remote_addr;" in text
        assert "proxy_set_header X-Forwarded-Proto $scheme;" in text
        assert "proxy_set_header X-Real-IP $remote_addr;" in text
        assert "proxy_set_header Host $host;" in text

    def test_proxy_vhost_renders_timeouts_and_failure_response(self):
        text = render_tenant_vhost(self._proxy_policy())
        # 0C.3
        assert "proxy_connect_timeout 5s;" in text
        assert "proxy_send_timeout 30s;" in text
        assert "proxy_read_timeout 30s;" in text
        assert "error_page 502 503 504" in text
        assert "edge_origin_unavailable" in text

    def test_proxy_vhost_renders_upgrade_negotiation(self):
        text = render_tenant_vhost(self._proxy_policy())
        # 0C.4
        assert "proxy_set_header Upgrade $http_upgrade;" in text
        assert "$connection_upgrade" in text

    def test_proxy_vhost_renders_body_size_and_no_compression(self):
        text = render_tenant_vhost(self._proxy_policy())
        # 0C.2 + 0C.5-adjacent compression position
        assert "client_max_body_size 1m;" in text
        assert "gzip off;" in text

    def test_body_size_bounded_by_node_capacity(self):
        assert NODE_MAX_BODY_SIZE == "10m"
        with pytest.raises(ValueError):
            self._proxy_policy(max_body_size="20m")

    def test_tenant_vhost_attaches_its_rules_file(self):
        text = render_tenant_vhost(self._proxy_policy())
        assert "modsecurity_rules_file /etc/nginx/tenants/acme.rules;" in text

    def test_vhosts_file_has_default_refuse_block(self):
        text = render_vhosts_file(load_policies())
        # 0D.2: unknown Host is refused explicitly, never served by the
        # first vhost that happens to exist
        assert "listen 80 default_server;" in text
        assert "return 421;" in text

    def test_vhosts_file_renders_upgrade_map_once(self):
        text = render_vhosts_file(load_policies())
        assert text.count("map $http_upgrade $connection_upgrade") == 1

    def test_vhosts_file_is_deterministic(self):
        assert render_vhosts_file(load_policies()) == render_vhosts_file(load_policies())

    def test_generated_vhosts_file_matches_rendered(self):
        generated = GENERATED_DIR / "vhosts.conf"
        assert generated.read_text(encoding="utf-8") == render_vhosts_file(load_policies()), (
            "vhosts.conf is stale; regenerate it from tenant-policies.json"
        )

    def test_policy_source_has_a_proxy_tenant(self):
        policies = load_policies()
        assert any(p.origin_url for p in policies), (
            "the policy source must contain at least one tenant with an origin "
            "(the 0D.1 proof tenant)"
        )

