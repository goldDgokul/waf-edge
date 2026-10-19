"""
0A.7(e) - a THIN, REAL auth test so quarantining the five dead test files does
not leave src/auth.py (a security boundary) at zero coverage.

The five quarantined files each tried to import `create_access_token` from
src.auth - a symbol that exists nowhere. They described an auth interface the
tenant redesign replaces. But the REAL AuthManager (src/auth.py) is live code
imported by main.py, and it must be exercised, or its defects (e.g. the
plaintext API-key log line, the 'admin123' default) are invisible to CI.

These tests exercise the real AuthManager - no mocking of the class under test -
covering the paths that matter: password hashing/verification, user
creation/authentication, API-key generation/verification/revocation, JWT
round-trip, and role checks.
"""

import pytest

from src.auth import AuthManager


@pytest.fixture()
def auth():
    """A fresh AuthManager; its module-level singleton is not reused."""
    return AuthManager()


def test_password_hash_round_trips(auth):
    hashed = auth.hash_password("hunter2secret")
    assert hashed != "hunter2secret"
    assert auth.verify_password("hunter2secret", hashed) is True
    assert auth.verify_password("wrong", hashed) is False


def test_create_and_authenticate_user(auth):
    auth.create_user("alice", "alice-password", ["viewer"])
    assert auth.authenticate_user("alice", "alice-password") is not None
    assert auth.authenticate_user("alice", "wrong-password") is None
    assert auth.authenticate_user("nobody", "x") is None


def test_duplicate_user_is_refused(auth):
    auth.create_user("bob", "pw", ["viewer"])
    with pytest.raises(Exception):
        auth.create_user("bob", "pw", ["viewer"])


def test_api_key_generate_verify_revoke(auth):
    auth.create_user("carol", "pw", ["operator"])
    key = auth.generate_api_key("carol")
    assert auth.verify_api_key(key) is not None
    assert auth.verify_api_key(key).username == "carol"
    assert auth.verify_api_key("not-a-real-key") is None
    assert auth.revoke_api_key(key) is True
    assert auth.verify_api_key(key) is None
    assert auth.revoke_api_key(key) is False


def test_jwt_round_trip(auth):
    auth.create_user("dave", "pw", ["admin"])
    token = auth.create_jwt_token("dave")
    data = auth.verify_jwt_token(token)
    assert data is not None
    assert data.username == "dave"
    assert "admin" in data.roles
    assert auth.verify_jwt_token("garbage") is None


def test_require_roles_enforces_roles(auth):
    checker = auth.require_roles(["admin"])
    from src.auth import TokenData
    from datetime import datetime, timedelta

    ok = TokenData(
        username="x", roles=["admin"], exp=datetime.now() + timedelta(hours=1)
    )
    assert checker(ok) is ok  # admin passes

    not_admin = TokenData(
        username="y", roles=["viewer"], exp=datetime.now() + timedelta(hours=1)
    )
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        checker(not_admin)
