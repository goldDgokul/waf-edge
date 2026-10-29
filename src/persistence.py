"""Durable control-plane storage (Phase 1.0).

One small sqlite3 database holding ONLY control-plane state (users, API
key hashes, generated rules, audit rows) so a process restart no longer
wipes customer identity and rules. Per the data-layer decision, high
volume threat/traffic telemetry stays in the Prometheus/Loki pipeline,
NOT here.

The store is deliberately generic: callers pass plain dicts/strings, so
the schema can be migrated to Postgres without touching the call sites.
"""

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    roles         TEXT NOT NULL,
    api_keys      TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    last_login    TEXT,
    is_active     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


def key_digest(api_key: str) -> str:
    """SHA-256 hex digest of an API key - the only form stored at rest."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class Store:
    """Durable store behind one WAL-mode sqlite3 connection.

    Args:
        db_path: filesystem path of the database file; parent directories
            are created.

    Raises:
        sqlite3.Error: if the file cannot be opened or the schema cannot
            be created - callers may fall back to memory-only operation.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def load_users(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM users").fetchall()
        return [dict(r) for r in rows]

    def save_user(
        self,
        username: str,
        password_hash: str,
        roles: List[str],
        api_key_hashes: List[str],
        created_at: datetime,
        last_login: Optional[datetime],
        is_active: bool,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    password_hash,
                    json.dumps(roles),
                    json.dumps(api_key_hashes),
                    created_at.isoformat(),
                    last_login.isoformat() if last_login else None,
                    1 if is_active else 0,
                ),
            )
            self._conn.commit()

    def delete_user(self, username: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM users WHERE username = ?", (username,))
            self._conn.execute("DELETE FROM api_keys WHERE username = ?", (username,))
            self._conn.commit()

    def load_api_keys(self) -> Dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT key_hash, username FROM api_keys").fetchall()
        return {r["key_hash"]: r["username"] for r in rows}

    def save_api_key(self, key_hash: str, username: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO api_keys VALUES (?, ?)", (key_hash, username)
            )
            self._conn.commit()

    def revoke_api_key(self, key_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM api_keys WHERE key_hash = ?", (key_hash,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def load_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT rule_id, payload FROM rules").fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def save_rules(self, rules: List[Tuple[str, Dict[str, Any]]]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM rules")
            self._conn.executemany(
                "INSERT INTO rules VALUES (?, ?)",
                [(rid, json.dumps(payload)) for rid, payload in rules],
            )
            self._conn.commit()

    def audit(self, actor: str, action: str, detail: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), actor, action, detail),
            )
            self._conn.commit()

    def load_audit(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, actor, action, detail FROM audit ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]