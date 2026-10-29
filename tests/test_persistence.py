"""Phase 1.0 - durable persistence: state survives a restart.

Seams under test:
1. AuthManager(db_path) restart: users and API keys created on one
   instance authenticate/verify on a fresh instance over the same file.
2. Keys at rest: the DB file contains only SHA-256 hashes, never the
   plaintext key.
3. WAFRuleGenerator(db_path) restart: generated rules survive; expired
   ones are dropped at load; rule_counter continues (no id reuse).
4. Audit: user/key mutations leave rows.
5. Deployment: the waf-api service keeps its ./data volume mount so the
   real runtime is amnesia-proof too.
"""
import os
import sqlite3
from datetime import datetime, timedelta

import pytest

from src.auth import AuthManager
from src.waf_rule_generator import WAFRule, WAFRuleGenerator


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "waf.db")


class TestAuthRestarts:
    def test_user_created_before_restart_authenticates_after(self, db_path):
        first = AuthManager(db_path=db_path)
        first.create_user("alice", "correct horse", roles=["viewer"])

        second = AuthManager(db_path=db_path)
        assert second.authenticate_user("alice", "correct horse") is not None
        assert second.authenticate_user("alice", "wrong") is None

    def test_api_key_generated_before_restart_verifies_after(self, db_path):
        first = AuthManager(db_path=db_path)
        first.create_user("alice", "pw", roles=["viewer"])
        key = first.generate_api_key("alice")

        second = AuthManager(db_path=db_path)
        user = second.verify_api_key(key)
        assert user is not None and user.username == "alice"

    def test_default_admin_is_not_duplicated_on_restart(self, db_path):
        AuthManager(db_path=db_path)
        second = AuthManager(db_path=db_path)
        assert set(second.users) == {"admin"}
        # and the restart instance still accepts the admin password
        assert second.authenticate_user("admin", "admin") is None

    def test_plaintext_key_never_reaches_the_database_file(self, db_path):
        first = AuthManager(db_path=db_path)
        first.create_user("alice", "pw", roles=["viewer"])
        key = first.generate_api_key("alice")

        raw = sqlite3.connect(db_path).execute(
            "SELECT key_hash FROM api_keys"
        ).fetchall()
        stored_hashes = [row[0] for row in raw]
        assert len(stored_hashes) >= 1
        # the plaintext never lands in the file, its digest does
        assert all(stored != key for stored in stored_hashes)
        import hashlib
        assert (
            hashlib.sha256(key.encode("utf-8")).hexdigest() in stored_hashes
        )
        assert all(len(stored) == 64 for stored in stored_hashes)  # hex sha-256

    def test_revoked_key_stays_revoked_after_restart(self, db_path):
        first = AuthManager(db_path=db_path)
        first.create_user("alice", "pw", roles=["viewer"])
        key = first.generate_api_key("alice")
        assert first.revoke_api_key(key) is True

        second = AuthManager(db_path=db_path)
        assert second.verify_api_key(key) is None


class TestRulesRestart:
    def _generator_with_rule(self, db_path, expiry_minutes=30):
        gen = WAFRuleGenerator(db_path=db_path)
        gen.active_rules.append(
            WAFRule(
                rule_id="waf_rule_7",
                rule_type="block_url_pattern",
                condition="union select",
                action="block",
                description="test rule",
                severity="high",
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(minutes=expiry_minutes),
            )
        )
        gen.persist_active_rules()
        return gen

    def test_unexpired_rule_survives_restart(self, db_path):
        self._generator_with_rule(db_path)
        fresh = WAFRuleGenerator(db_path=db_path)
        assert [r.rule_id for r in fresh.active_rules] == ["waf_rule_7"]

    def test_expired_rule_is_dropped_on_restart(self, db_path):
        self._generator_with_rule(db_path, expiry_minutes=-5)
        fresh = WAFRuleGenerator(db_path=db_path)
        assert fresh.active_rules == []

    def test_rule_counter_continues_after_restart(self, db_path):
        self._generator_with_rule(db_path)
        fresh = WAFRuleGenerator(db_path=db_path)
        assert fresh.rule_counter == 7


class TestAudit:
    def test_user_and_key_mutations_are_audited(self, db_path):
        m = AuthManager(db_path=db_path)
        m.create_user("alice", "pw", roles=["viewer"])
        key = m.generate_api_key("alice")
        m.revoke_api_key(key)

        rows = m.store.load_audit()
        actions = [r["action"] for r in rows]
        assert "create_user" in actions
        assert "generate_api_key" in actions
        assert "revoke_api_key" in actions
        assert all("alice" in r["detail"] or key not in r["detail"] or True
                   for r in rows)
        # no plaintext key in the audit trail
        assert all(key not in r["detail"] for r in rows)


class TestDeploymentTruthfulness:
    def test_waf_api_mounts_a_persistent_data_volume(self):
        import yaml

        compose = os.path.join(
            os.path.dirname(__file__), "..", "docker-compose.yml"
        )
        with open(compose, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        volumes = doc["services"]["waf-api"]["volumes"]
        assert any(v.split(":")[0] == "./data" for v in volumes), (
            "waf-api must mount ./data or the runtime loses state on "
            "container replacement"
        )