"""Phase 0A.6 security behaviour tests against the real shipped artifacts."""

from pathlib import Path
import uuid

import pytest
from fastapi.testclient import TestClient

from src.auth import auth_manager
from src.main import app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PANEL_HTML = PROJECT_ROOT / "docker" / "control-panel" / "control-panel.html"
PANEL_NGINX = PROJECT_ROOT / "docker" / "control-panel" / "nginx.conf"


@pytest.fixture()
def client():
    return TestClient(app, base_url="http://localhost")


def _create_user(roles):
    username = f"phase0a6-{uuid.uuid4().hex}"
    password = "phase0a6-valid-password"
    auth_manager.create_user(username, password, roles)
    return username, password


def _remove_user(username):
    user = auth_manager.users.pop(username, None)
    if user:
        for api_key in user.api_keys:
            auth_manager.api_keys.pop(api_key, None)


def _bearer_headers(roles):
    username, _ = _create_user(roles)
    token = auth_manager.create_jwt_token(username)
    return username, {"Authorization": f"Bearer {token}"}


def test_login_accepts_valid_credentials_and_returns_bearer_token(client):
    """The public login route authenticates a real AuthManager user."""
    username, password = _create_user(["viewer"])

    try:
        response = client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
    finally:
        _remove_user(username)

    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    assert isinstance(payload["access_token"], str)
    token_data = auth_manager.verify_jwt_token(payload["access_token"])
    assert token_data is not None
    assert token_data.username == username


def test_invalid_login_returns_401_not_500(client):
    response = client.post(
        "/auth/login",
        json={"username": "not-a-real-user", "password": "wrong-password"},
    )

    assert response.status_code == 401


def test_repeated_invalid_logins_are_rate_limited(client):
    statuses = [
        client.post(
            "/auth/login",
            json={"username": "not-a-real-user", "password": "wrong-password"},
        ).status_code
        for _ in range(30)
    ]

    assert 429 in statuses


@pytest.mark.parametrize("path", ["/api/status", "/api/nodes", "/api/rules"])
def test_viewer_routes_reject_missing_token(client, path):
    assert client.get(path).status_code == 401


def test_admin_route_rejects_viewer_token(client):
    username, headers = _bearer_headers(["viewer"])
    try:
        response = client.get("/auth/users", headers=headers)
    finally:
        _remove_user(username)

    assert response.status_code == 403


@pytest.mark.parametrize("path", ["/", "/health", "/metrics"])
def test_public_routes_remain_public(client, path):
    assert client.get(path).status_code == 200


def test_api_health_returns_truthful_non_500_response(client):
    username, headers = _bearer_headers(["viewer"])
    try:
        response = client.get("/api/health", headers=headers)
    finally:
        _remove_user(username)

    assert response.status_code == 200
    assert response.json()["system_status"] in {
        "healthy",
        "degraded",
        "critical",
        "failing",
    }


@pytest.mark.parametrize(
    "path",
    [
        "/openapi.json",
        "/test-no-auth",
        "/api/debug/traffic-collector",
        "/api/debug/status",
    ],
)
def test_closed_routes_are_not_served(client, path):
    assert client.get(path).status_code == 404


def test_fastapi_cors_rejects_unapproved_credentialed_origin(client):
    response = client.options(
        "/api/status",
        headers={
            "Origin": "https://unapproved.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_panel_proxy_has_no_wildcard_cors():
    config = PANEL_NGINX.read_text(encoding="utf-8")

    assert "Access-Control-Allow-Origin' '*'" not in config


def test_panel_waits_for_login_and_sends_bearer_token():
    panel = PANEL_HTML.read_text(encoding="utf-8")

    assert 'id="login-form"' in panel
    assert "DOMContentLoaded', initializeApp" not in panel
    assert "Authorization" in panel
    assert "Bearer ${" in panel

def test_api_key_is_not_accepted_as_a_bearer_token(client):
    """H1: bearer credentials are verified JWTs only.

    The issued API keys never expire and no route issues new ones, so they
    must not silently act as eternal bearer tokens on 0A.6-guarded routes.
    """
    key = auth_manager.generate_api_key("admin")

    response = client.get(
        "/api/status",
        headers={"Authorization": f"Bearer {key}"},
    )

    assert response.status_code == 401


def _fake_request(peer, real_ip=None):
    from fastapi import Request

    headers = {"x-real-ip": real_ip} if real_ip else {}
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/auth/login",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (peer, 51234),
        "query_string": b"",
        "server": ("waf-api", 8000),
        "scheme": "http",
    }
    return Request(scope)


def test_real_client_ip_uses_forwarded_ip_from_trusted_proxy(monkeypatch):
    """H2: browsers behind the panel proxy share the proxy's IP; the real
    per-client distinction arrives in X-Real-IP and must be honoured when
    the direct peer really is the trusted control-panel container."""
    monkeypatch.setattr(import_module("src.main"), "_trusted_proxies", lambda: {"10.42.0.9"})

    request = _fake_request("10.42.0.9", "77.10.1.2")

    assert real_client_ip(request) == "77.10.1.2"


def test_real_client_ip_rejects_forwarded_from_untrusted_peer(monkeypatch):
    """H2: a direct caller must not be able to rotate its rate-limit bucket
    by sending a forged X-Real-IP header."""
    monkeypatch.setattr(import_module("src.main"), "_trusted_proxies", lambda: {"10.42.0.9"})

    request = _fake_request("6.6.6.6", "77.10.1.2")

    assert real_client_ip(request) == "6.6.6.6"


def test_login_rate_limit_is_per_real_ip_not_per_proxy(client, monkeypatch):
    user, _ = _create_user(["viewer"])
    monkeypatch.setattr(import_module("src.main"), "_trusted_proxies", lambda: {"testclient"})
    ip_a = f"77.1.{uuid.uuid4().int % 250 + 1}.1"
    ip_b = f"77.2.{uuid.uuid4().int % 250 + 1}.1"

    statuses_a = [
        client.post("/auth/login", json={"username": user, "password": "wrong"}, headers={"X-Real-IP": ip_a}).status_code
        for _ in range(6)
    ]
    status_b = client.post("/auth/login", json={"username": user, "password": "wrong"}, headers={"X-Real-IP": ip_b}).status_code

    assert statuses_a[:5] == [401] * 5
    assert statuses_a[5] == 429
    assert status_b == 401
from importlib import import_module
from src.main import real_client_ip



def test_no_exception_details_leak_in_500_responses():
    """H4: exception strings must not travel to API error responses; they
    can expose file paths, SQL fragments or internal topology. Handlers log
    the cause server-side; the response detail stays generic."""
    import re

    source_files = [PROJECT_ROOT / "src" / "main.py", PROJECT_ROOT / "src" / "auth.py"]
    offenders = []
    for source in source_files:
        for index, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"HTTPException\(.*detail=f\"[^\"]*\{str\(", line,):
                offenders.append(f"{source.name}:L{index}: {line.strip()}")
    assert not offenders, "exception text leaks into 500 details:\n" + "\n".join(offenders)
