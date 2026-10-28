# ADR 0003: tenant policy model - per-tenant ModSecurity rules files via `modsecurity_rules_file`

Date: 2026-10-28. Status: ACCEPTED.

## Context

Plan v7.5 0B.6: "Design rule exclusions, sensitivity and quotas so they can
become tenant-scoped later; do not create another global-only rule model that
Phase 2 must replace."

The shipped nodes now run OWASP CRS (ADR 0002). CRS exclusion management has a
well-known failure mode: exclusions added to a shared override file are global,
so an exclusion one tenant needs weakens every other tenant's protection. The
design must make the tenant boundary structural, not a convention.

## Decision

1. A tenant's policy - sensitivity (CRS paranoia level), rule exclusions
   (tenant-wide `SecRuleRemoveById` and path-scoped `ctl:ruleRemoveById`),
   and an optional request rate limit - is a single `TenantPolicy` object in
   `src/tenant_policy.py`, sourced from
   `docker/shared/tenant-policies.json`.
2. Each policy renders to ONE generated file per tenant
   (`docker/shared/tenant-policies/<tenant>.rules`) and is attached at SERVER
   scope in that tenant's vhost via the ModSecurity-nginx connector's native
   `modsecurity_rules_file` directive. The connector evaluates those rules
   only for that server block: tenant scoping is enforced by nginx itself,
   not by convention.
3. The generated files are checked in, and a test regenerates them from the
   policy source and fails on any drift (same discipline as the config hash
   tripwires). Path-scoped exclusion rule ids are allocated deterministically
   from the CRS local range (100000+) in source order.
4. Rate limits render as `limit_req zone=tenant-<id>` lines in the same
   vhost snippet; a tenant without a quota renders no limit_req directive.

## Consequences

- Adding a tenant is additive: one JSON entry, one generated file, one vhost
  snippet. No shared override file is ever edited per tenant, so no
  exclusion can leak across tenants by construction.
- The per-tenant file is where future tenant knobs (response inspection,
  targeted rule tags) belong; the model (sensitivity/exclusions/quotas) is
  the Phase 2 interface, not a placeholder to replace.
- Today the two shipped nodes each have a default tenant policy at CRS
  default sensitivity (paranoia level 1) with no exclusions - the shipped
  protection posture is unchanged by this ADR, and the corpus gate
  (tests/test_edge_corpus.py) plus the published measurement
  (docs/guide/measurement.md) prove it.
- Exclusions are deliberately NOT added yet: ADR 0002 gates production
  adoption on exclusion tuning against representative traffic. When that
  tuning happens, it happens per tenant in tenant-policies.json.
