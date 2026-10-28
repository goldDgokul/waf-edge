# ADR 0002: adopt OWASP CRS (ModSecurity v3 + nginx connector) as the deterministic baseline

Date: 2026-10-28. Status: ACCEPTED (bounded spike evidence recorded; production
adoption still gated on the plan v7.5 requirements below).

## Context

Plan v7.5 [PRODUCT RULE]: the product must use a proven deterministic WAF
baseline as its first line of inspection; AI detection must never be the only
foundation for blocking known attack classes. 0B.0 required a bounded spike
comparing OWASP CRS + a compatible nginx engine against the internally
maintained signature baseline (today: three `map` blocks in
`docker/shared/waf-rules/basic.conf`).

The measured 0B.4 corpus (tests/test_edge_corpus.py) encodes the bypasses
measured against the internal baseline: encoded/double-encoded literals,
`OR 1=1`, traversal queries, POST-body SQLi, XSS in User-Agent and Cookie.

## Spike evidence (measured 2026-10-28)

Official OWASP image `owasp/modsecurity-crs:nginx`
(ModSecurity v3.0.17, ModSecurity-nginx v1.0.4, OWASP_CRS/4.30.0, nginx
1.30.6, paranoia level 1, default config, no backend — 502 = request passed
the engine and hit the missing upstream):

| Corpus entry                        | Internal baseline | CRS image |
|-------------------------------------|-------------------|-----------|
| xss-percent-encoded-javascript      | 200 (bypass)      | 403 (941210/941170/941390) |
| xss-double-encoded-script           | 200 (bypass)      | 403 (941100/941110/941160) |
| sqli-or-1eq1                        | 200 (bypass)      | 403 (942100 libinjection) |
| traversal-dotdot-query              | 200 (bypass)      | 403 (930100/930110/930120/932160) |
| xss-user-agent-header               | 200 (bypass)      | 403 (941100/941110/941160) |
| xss-cookie-header                   | 200 (bypass)      | 403 (941100/941110/941160/941390) |
| safe-word-union / safe-root         | 200               | 502 (passed engine) |
| extension-near-match (.env.bak)     | 200               | 403 FALSE POSITIVE (920440 restricted extension) |
| sqli-post-body (weak payload)       | 200 (bypass)      | 502 (also passed CRS — honest CRS miss on that payload) |

## Decision

1. ADOPT the CRS engine as the deterministic baseline for Phase 0B+: CRS
   coverage at paranoia level 1 blocks every measured encoded/placement
   bypass class the internal baseline misses, on the shipped official image,
   without custom signatures.
2. KEEP the internal static maps and the generated-rule pipeline as an
   additional tenant-scoped layer on top of the baseline (block-only
   semantics, existing stage→test→activate→verify→rollback chain).
3. The 0B.4 corpus is the regression gate for integration: all STILL BLOCKED
   entries must stay blocked, SAFE TRAFFIC must stay allowed, and BYPASS
   xfails are promoted to plain assertions once the baseline is wired in.
   The CRS false positive (.env.bak / 920440) must be resolved by an explicit
   exclusion/tuning policy, not by ignoring the corpus test.

## Operational costs recorded (not yet paid)

- Two policy systems: CRS baseline exclusions + generated tenant rules. Per
  tenant exclusion/sensitivity configuration (0B.6) is required so rules can
  become tenant-scoped without another global-only model.
- CRS false positives need representative legitimate traffic for tuning;
  synthetic traffic alone cannot approve production behaviour (plan gate).
- libmodsecurity v3 maintenance posture and the nginx connector maturity must
  be re-verified from primary sources before fleet rollout; if maintenance
  evidence becomes inconclusive, the fallback is the internal deterministic
  baseline extended in measured 0B.2 slices.

## Consequences

- 0B.1/0B.2 implementation shifts from "hand-create canonicalisation
  signatures" to "wire the CRS engine in front of the existing config and
  tune exclusions", with the corpus guarding both directions.
- ML candidates (out of band) may propose rules on top of the baseline only;
  the enforce-or-delete decision for WAFRule.action (0B) is still open.
