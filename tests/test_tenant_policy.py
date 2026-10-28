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
    render_vhost_snippet,
    validate_policies,
    POLICIES_SOURCE,
    GENERATED_DIR,
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
