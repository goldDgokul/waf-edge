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
