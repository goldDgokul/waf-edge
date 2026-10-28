"""0B.6: tenant policy model (exclusions, sensitivity, quotas).

Plan v7.5 0B.6: "Design rule exclusions, sensitivity and quotas so they
can become tenant-scoped later; do not create another global-only rule
model that Phase 2 must replace."

Design decision (ADR 0003): tenant policy is a per-tenant object rendered
to a per-tenant ModSecurity rules file, attached at SERVER scope via the
connector's native `modsecurity_rules_file` directive. Everything a
tenant can influence - sensitivity (CRS paranoia level), rule exclusions
(global-to-that-tenant and path-scoped), and an optional request rate
limit - renders into THAT tenant's file only. Adding a tenant adds one
file and one vhost snippet; nothing is a shared mutable dump that Phase 2
would have to replace.

Rule ids for path-scoped ctl exclusions are allocated from the CRS
convention's local range (100000+) in corpus order, so rendering is
deterministic and reviewable.

Sources and artifacts:
    docker/shared/tenant-policies.json   - policy source of truth (checked in)
    docker/shared/tenant-policies/<id>.rules - generated, checked in;
        tests/test_tenant_policy.py fails if a generated file is stale.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_SOURCE = REPO_ROOT / "docker" / "shared" / "tenant-policies.json"
GENERATED_DIR = REPO_ROOT / "docker" / "shared" / "tenant-policies"

# CRS reserves 1xxxxx for local custom rules; ctl exclusions get ids here.
CTL_RULE_ID_BASE = 100000

# 0C.2 (EC2): a tenant body-size ceiling is bounded by node capacity.
NODE_MAX_BODY_SIZE = "10m"


def _parse_size(value: str) -> int:
    """Parse an nginx size literal ('1m', '512k', '4096') into bytes."""
    match = re.fullmatch(r"(\d+)([km]?)", str(value))
    if not match:
        raise ValueError(f"invalid size literal {value!r} (use e.g. '1m', '512k')")
    number, unit = int(match.group(1)), match.group(2)
    return number * {"": 1, "k": 1024, "m": 1024 * 1024}[unit]


@dataclass(frozen=True)
class RuleExclusion:
    rule_id: str
    path_prefix: Optional[str] = None

    def __post_init__(self):
        if not self.rule_id.isdigit():
            raise ValueError(f"rule_id must be numeric, got {self.rule_id!r}")


@dataclass(frozen=True)
class RateLimit:
    rate: int      # requests per second
    burst: int = 0

    def __post_init__(self):
        if self.rate <= 0:
            raise ValueError(f"rate must be positive, got {self.rate}")
        if self.burst < 0:
            raise ValueError(f"burst must be >= 0, got {self.burst}")


@dataclass(frozen=True)
class TenantPolicy:
    tenant_id: str
    hostname: str
    sensitivity: int = 1          # CRS paranoia level 1..4
    exclusions: Tuple[RuleExclusion, ...] = ()
    rate_limit: Optional[RateLimit] = None
    # 0D.1: a tenant with an origin_url gets a proxy vhost rendered for it;
    # a tenant without one keeps only its ModSecurity rules file (demo
    # tenants keep their canned vhosts from waf-node.conf).
    origin_url: Optional[str] = None
    # 0C.2: per-tenant body size, bounded by node capacity.
    max_body_size: str = "1m"

    def __post_init__(self):
        if not self.tenant_id:
            raise ValueError("tenant_id must be non-empty")
        if not self.hostname:
            raise ValueError("hostname must be non-empty")
        if self.sensitivity not in (1, 2, 3, 4):
            raise ValueError(f"sensitivity must be 1..4, got {self.sensitivity}")
        if _parse_size(self.max_body_size) > _parse_size(NODE_MAX_BODY_SIZE):
            raise ValueError(
                f"max_body_size {self.max_body_size} exceeds node capacity "
                f"{NODE_MAX_BODY_SIZE}")


def validate_policies(policies: List[TenantPolicy]) -> List[TenantPolicy]:
    """Reject duplicate tenant ids and duplicate hostnames."""
    seen_ids, seen_hosts = set(), set()
    for policy in policies:
        if policy.tenant_id in seen_ids:
            raise ValueError(f"duplicate tenant_id {policy.tenant_id!r}")
        if policy.hostname in seen_hosts:
            raise ValueError(f"duplicate hostname {policy.hostname!r}")
        seen_ids.add(policy.tenant_id)
        seen_hosts.add(policy.hostname)
    return policies


def load_policies(path: Optional[Path] = None) -> List[TenantPolicy]:
    """Load the checked-in policy source into validated policy objects."""
    source = path or POLICIES_SOURCE
    with open(source, encoding="utf-8") as handle:
        raw = json.load(handle)
    policies = [
        TenantPolicy(
            tenant_id=item["tenant_id"],
            hostname=item["hostname"],
            sensitivity=item.get("sensitivity", 1),
            exclusions=tuple(
                RuleExclusion(rule_id=ex["rule_id"],
                              path_prefix=ex.get("path_prefix"))
                for ex in item.get("exclusions", ())
            ),
            rate_limit=(
                RateLimit(rate=item["rate_limit"]["rate"],
                          burst=item["rate_limit"].get("burst", 0))
                if item.get("rate_limit") else None
            ),
            origin_url=item.get("origin_url"),
            max_body_size=item.get("max_body_size", "1m"),
        )
        for item in raw["tenants"]
    ]
    return validate_policies(policies)


def _ctl_exclusion_id(index: int) -> int:
    """Deterministic local id for the path-scoped exclusion at `index`."""
    return CTL_RULE_ID_BASE + index


def render_rules_file(policy: TenantPolicy) -> str:
    """Render ONE tenant's ModSecurity rules file (per-tenant scope only).

    Args:
        policy: the tenant whose sensitivity/exclusions are rendered.

    Returns:
        The file content as a string; contains only this tenant's
        directives.
    """
    lines = [
        f"# Tenant: {policy.tenant_id} ({policy.hostname})",
        "# Generated by src/tenant_policy.py - edit tenant-policies.json,",
        "# not this file. Attached at server scope via modsecurity_rules_file.",
        "",
        "# Tenant sensitivity: CRS paranoia level.",
        f'SecAction "id:900118,phase:1,pass,t:none,nolog,'
        f'setvar:tx.paranoia_level={policy.sensitivity}"',
        "",
    ]
    if not policy.exclusions:
        lines.append("# No exclusions for this tenant.")
        return "\n".join(lines) + "\n"

    lines.append("# Rule exclusions, tenant-scoped only.")
    for exclusion in policy.exclusions:
        if exclusion.path_prefix:
            index = policy.exclusions.index(exclusion)
            lines.append(
                f'SecRule REQUEST_FILENAME "@beginsWith {exclusion.path_prefix}" '
                f'"id:{_ctl_exclusion_id(index)},'
                f'phase:1,pass,nolog,ctl:ruleRemoveById={exclusion.rule_id},'
                f'tag:tenant-{policy.tenant_id}"'
            )
        else:
            lines.append(f"SecRuleRemoveById {exclusion.rule_id}")
    return "\n".join(lines) + "\n"


def render_vhost_snippet(policy: TenantPolicy) -> str:
    """Render the vhost lines that attach the tenant policy.

    Args:
        policy: the tenant to attach.

    Returns:
        Snippet text: modsecurity_rules_file plus an optional limit_req.
    """
    lines = [
        "# 0B.6 (ADR 0003): tenant-scoped policy for this vhost.",
        f"modsecurity_rules_file /etc/nginx/tenants/{policy.tenant_id}.rules;",
    ]
    if policy.rate_limit:
        lines.append(
            f"limit_req zone=tenant-{policy.tenant_id} "
            f"burst={policy.rate_limit.burst} nodelay;"
        )
    return "\n".join(lines)


def render_tenant_vhost(policy: TenantPolicy) -> str:
    """0D.1: render ONE tenant's proxy server block. Tenants without an
    origin render nothing (their hostname stays owned by the demo vhost;
    a duplicate server_name would be a misconfiguration, not a feature).

    Args:
        policy: the tenant to render.

    Returns:
        The server-block text, or "" when the policy has no origin_url.
    """
    if not policy.origin_url:
        return ""
    lines = [
        "server {",
        "    listen 80;",
        f"    server_name {policy.hostname};",
        "",
        f"    # tenant: {policy.tenant_id} (sensitivity {policy.sensitivity})",
        f"    client_max_body_size {policy.max_body_size};",
        "    # 0C.5 position: caching is refused for the first release (ADR 0004).",
        "    gzip off;",
        "",
        "    modsecurity_rules_file /etc/nginx/tenants/" + policy.tenant_id + ".rules;",
        "",
        "    location / {",
        f"        # resolved at runtime via the docker embedded resolver so the",
        f"        # edge starts even when an origin is down (then 502, EC3).",
        f"        set $origin_upstream {policy.origin_url};",
        f"        resolver 127.0.0.11 valid=10s ipv6=off;",
        f"        proxy_pass $origin_upstream;",
        "        proxy_http_version 1.1;",
        "        # 0C.1 (EC1) trust policy: the edge OVERWRITES any",
        "        # client-supplied forwarding headers with what it observed.",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Forwarded-For $remote_addr;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        # 0C.4 (EC4): upgrade negotiation is forwarded; upgraded frames",
        "        # pass AFTER CRS inspected the upgrade request itself.",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $connection_upgrade;",
        "        # 0C.3 (EC3) timeouts",
        "        proxy_connect_timeout 5s;",
        "        proxy_send_timeout 30s;",
        "        proxy_read_timeout 30s;",
        "    }",
        "",
        "    # 0C.3 (EC3) defined origin-failure response; alerting consumes the",
        "    # access-log 502/504 stream shipped by promtail.",
        "    error_page 502 503 504 =502 @origin_failure;",
        "    location @origin_failure {",
        "        default_type application/json;",
        "        return 200 '{\"error\":\"edge_origin_unavailable\"}';",
        "    }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def render_vhosts_file(policies: List[TenantPolicy]) -> str:
    """0D: the generated conf.d file - upgrade map (once), a default server
    that REFUSES unknown hosts (0D.2), and one server block per proxy
    tenant (0D.1).

    Args:
        policies: validated tenant policies.

    Returns:
        The generated conf.d file content.
    """
    lines = [
        "# GENERATED by src/tenant_policy.py from docker/shared/tenant-policies.json",
        "# - edit the JSON source, not this file; staleness is tested.",
        "# 0D.1/0D.2 (ADR 0004): tenant vhosts + explicit default refusal.",
        "",
        "# 0C.4 (EC4): upgrade negotiation map, http scope, rendered once.",
        "map $http_upgrade $connection_upgrade {",
        "    default upgrade;",
        "    ''      close;",
        "}",
        "",
        "# 0D.2 (T11): a Host/SNI matching no tenant must be REFUSED -",
        "# never served by whichever vhost happens to be first.",
        "server {",
        "    listen 80 default_server;",
        "    server_name _;",
        "    return 421;",
        "}",
        "",
    ]
    for policy in policies:
        vhost = render_tenant_vhost(policy)
        if vhost:
            lines.append(vhost)
    return "\n".join(lines) + "\n"
