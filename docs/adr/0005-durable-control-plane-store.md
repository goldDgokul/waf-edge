# ADR 0005: durable control-plane store - stdlib SQLite, hashed API keys, write-through

Date: 2026-10-29. Status: ACCEPTED.

## Context

Phase 1.0 (plan v7.5): tenant state lives in process memory in two modules -
`src/auth.py` (`self.users`, `self.api_keys`) and `src/waf_rule_generator.py`
(`self.active_rules`) - so a restart wipes customer identity and generated
rules. A hosted multi-tenant product cannot ship with amnesia, and identity
must be designed against an approved data layer, not a process-local
dictionary.

The plan's Decision D (Section 7) is marked OPEN: managed relational database,
Convex as the system of record, or an existing internal database service.
Section 7 additionally partitions data into three classes: control-plane data
(referential integrity, queries, access control), secrets (dedicated storage),
and high-volume telemetry (belongs in the Prometheus/Loki pipeline, never in
the control-plane store).

## Decision

1. **SQLite via the standard library** is the control-plane store for Phase 1.
   No new dependency (SQLAlchemy and Convex are not in the pinned
   requirements); a single WAL-mode connection guarded by a threading lock
   (`src/persistence.py`); the file lives on the already-mounted `./data`
   volume, path configured by `WAF_DB_PATH` (default `data/waf.db`).
   The call sites pass plain dicts and strings, so moving to Postgres is a
   store rewrite, not a redesign. Convex remains what the plan already
   decided it to be: the dashboard direction, not the system of record.
2. **Control-plane data only** (plan 1.1's "tenant_id on threats" is
   re-scoped): users, API-key digests, generated rules, and audit rows go in
   the store. Threat/traffic telemetry stays out - its tenant dimension
   arrives in Phase 2.5 as a log/metric label.
3. **API keys are stored as SHA-256 digests** (Q2): keys are high-entropy
   `token_urlsafe` values, so the plaintext exists only in the response at
   generation time. The in-memory maps and the `api_keys` table hold
   `digest -> username`.
4. **Write-through, hydrate on start**: the existing in-memory structures
   stay the live state (smallest change); every mutation (user create,
   login, key generate/revoke, rule generate/cleanup/limit-enforcement)
   writes through, and components hydrate on construction. The default
   admin is created only when the store has no users, so a restart neither
   duplicates nor resets it.
5. **Generated rules persist with expiry honored**: `active_rules` are
   written with their `expires_at`; on reload, expired rules are dropped and
   the rule counter resumes past the highest persisted id so an id is never
   reused.
6. **A minimal audit table** (`ts, actor, action, detail`) ships with 1.0,
   written on user/key mutations; details never carry a plaintext key. The
   full audit view is plan item 1.5.

## Consequences

- A restart no longer loses users, keys, or rules - proven live: a user
  created via the API authenticated after `docker restart waf-api`
  (2026-10-29), with the admin not duplicated.
- Test sessions are isolated: `tests/conftest.py` points `WAF_DB_PATH` at a
  per-session temp file BEFORE any `src` import; the suite stays green
  across consecutive runs. The repo's `data/` directory never enters git
  (`data/*.db*` ignored).
- If the store cannot be opened, components log a warning and run
  memory-only - degraded, not down.
- Rules that expire within their TTL behave exactly as before; persistence
  changes lifetime semantics for nothing else.
- Risks accepted for the pilot: single-file storage with no off-host backup
  (operational readiness is a cross-cutting plan item), and WAL files living
  next to the database on the same volume.