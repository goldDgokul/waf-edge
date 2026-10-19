"""
0A.10 point 7 - the log parser categorises the three request outcomes.

A request is one of: ALLOWED (reaches the backend), WAF-BLOCKED (a WAF rule
returns 403/404 and the log carries the rule id + reason), or BACKEND-403 (the
backend returns its own 403, which the WAF must NOT claim). The parser must
distinguish them so the dashboard can show a true "Blocked Requests" view that is
not polluted by backend 403s, and so a WAF block is attributable to its rule.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "docker" / "log-server"))
from app import parse_nginx_log_line  # noqa: E402


def _line(path, status, host="tenant.example.com", rule_id="-", reason="-"):
    return (
        f'1.2.3.4 - - [19/Oct/2026:05:45:01 +0000] "GET {path} HTTP/1.1" '
        f'{status} 153 "-" "curl/8.18.0" 0.000 - 100 500 {host} {rule_id} {reason}'
    )


def test_allowed_request_has_no_waf_attribution():
    r = parse_nginx_log_line(_line("/api/users", 200))
    assert r["status"] == 200
    assert r["waf_rule_id"] == "-"
    assert r["waf_reason"] == "-"


def test_waf_blocked_request_carries_rule_id_and_reason():
    r = parse_nginx_log_line(_line("/search?q=union+select", 403, rule_id="static_sql_injection", reason="sql_injection"))
    assert r["status"] == 403
    assert r["waf_rule_id"] == "static_sql_injection"
    assert r["waf_reason"] == "sql_injection"


def test_backend_403_is_not_attributed_to_waf():
    # A backend's own 403 (e.g. /admin/config) logs the same status but NO rule id.
    r = parse_nginx_log_line(_line("/admin/config", 403))
    assert r["status"] == 403
    assert r["waf_rule_id"] == "-"
    assert r["waf_reason"] == "-"


def test_tenant_host_is_extracted_alongside_attribution():
    r = parse_nginx_log_line(_line("/x", 403, host="acme.example.com", rule_id="r1", reason="block_url_pattern"))
    assert r["host"] == "acme.example.com"
    assert r["waf_rule_id"] == "r1"


def test_backward_compatible_without_attribution_tail():
    # A log line written before the 0A.10 fields existed must still parse.
    line = (
        '1.2.3.4 - - [19/Oct/2026:05:45:01 +0000] "GET /api/users HTTP/1.1" '
        '200 153 "-" "curl" 0.000 - 100 500 tenant.example.com'
    )
    r = parse_nginx_log_line(line)
    assert r["status"] == 200
    assert r["waf_rule_id"] == "-"
    assert r["waf_reason"] == "-"
