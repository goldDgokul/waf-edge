---
status: accepted
date: 2026-10-27
---

# JWTs are verified statelessly, without a live user-registry hit

A bearer token issued by `/auth/login` authenticates if its signature and expiry
are valid, even if the user was later removed from the in-memory user registry.
Phase 0A's auth users are in-memory only, so keeping the registry check would
have silently invalidated every valid token on every API restart. The
statelessness trade-off (a deleted user keeps access until expiry in this
in-memory-user phase) is accepted for now.

## Considered Options

- **Signature + expiry only** (chosen): matches how the 0A.6 RED spec
  (`tests/test_security_0a6.py`) defines token validity.
- **Signature + expiry + live user lookup**: rejected — no persistence below
  the in-memory registry means restarts would reject tokens minted minutes
  before, which the acceptance tests reject.

## Consequences

Revoking a user's access requires an invalidation story (denylist or persisted
users); the Phase 0A in-memory registry alone is not one. When the
multi-tenant identity system lands, this ADR should be revisited.
