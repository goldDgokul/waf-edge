"""
0A.9 - the rule INPUT path must reject values that would be injected into nginx
config, rather than emitting them verbatim.

The one attacker-influenced free-form value that reaches to_nginx_config is the
IP in a block_ip rule (embedded as `if ($remote_addr = "{ip}")`). A valid
$remote_addr is always a real IP, but the value is a free-form string, so a
malformed or malicious source_ip would be injected into the config. This locks in
the guard that rejects anything that is not a single IPv4/IPv6 address.
"""

import pytest

from src.waf_rule_generator import WAFRuleGenerator


@pytest.fixture()
def gen():
    return WAFRuleGenerator()


def test_valid_ipv4_is_accepted(gen):
    assert gen._generate_ip_block_rule("1.2.3.4", 5) is not None


def test_valid_ipv6_is_accepted(gen):
    assert gen._generate_ip_block_rule("2001:db8::1", 5) is not None


@pytest.mark.parametrize(
    "malicious",
    [
        '1.2.3.4"; return 403; #',  # config injection
        "1.2.3.0/24",                # CIDR: exact-match `=` never fires
        "not-an-ip",
        "",
        "1.2.3.4\n set $waf_blocked 403;",
    ],
)
def test_non_ip_and_injection_values_are_rejected(gen, malicious):
    assert gen._generate_ip_block_rule(malicious, 5) is None, (
        f"{malicious!r} must be rejected, not embedded into nginx config"
    )


def test_rejected_ip_does_not_reach_active_rules(gen):
    # Drive the public entry point with 5 threats from a malicious source_ip; the
    # rule must NOT appear in active_rules.
    threats = [
        {"source_ip": '1.2.3.4"; return 403; #', "threat_type": "sql_injection"}
        for _ in range(5)
    ]
    gen.generate_rules_from_threats(threats, {})
    assert all(r.rule_type != "block_ip" for r in gen.active_rules), (
        "a malicious source_ip must not produce a block_ip rule"
    )
