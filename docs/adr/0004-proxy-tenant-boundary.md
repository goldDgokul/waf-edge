# ADR 0004: data-plane tenant boundary (tenant vhosts, default refusal) and the proxy-correctness positions

Date: 2026-10-28. Status: ACCEPTED.

## Context

Plan v7.5 Phase 0C/0D: the edge claims to be a reverse proxy that forwards to
customer origins, but measured 2026-10-16 there was no `proxy_pass` anywhere
in the shipped node configuration - the edge could not host a customer at
all. 0C requires the proxy-correctness harness (0C.9) so every claim is
verified by observation; 0D requires a tenant vhost that proxies (0D.1), a
default vhost that refuses unknown hosts (0D.2), and the observed
verification of both (0D.3).

## Decision

### Tenant vhosts (0D.1)
Tenant proxy vhosts are GENERATED from the tenant policy model
(`src/tenant_policy.py`, ADR 0003) into one checked-in file
(`docker/shared/tenant-policies/vhosts.conf`, mounted at
`/etc/nginx/conf.d/waf-tenants.conf`). A tenant policy WITH an `origin_url`
renders a full proxy server block; without one, it renders nothing (demo
tenants keep the canned vhosts - a generated duplicate `server_name` would
be a misconfiguration, not a feature).

The upstream is resolved at RUNTIME via the docker embedded resolver
(`set $origin_upstream ...; resolver 127.0.0.11 ...; proxy_pass
$origin_upstream;`) so the edge starts even when an origin is down - an
origin outage then produces the defined 502 response, not an unstartable
edge.

### Default refusal (0D.2)
The generated file contains a `listen 80 default_server; server_name _;`
block that returns **421 Misdirected Request** for any Host/SNI matching no
tenant. A request for an unknown host is never served by whichever vhost
happens to be first (T11: Host-header tenant confusion is a
tenant-isolation property, not a nicety).

### Forward client identity (0C.1, EC1)
The edge sets `Host $host`, `X-Forwarded-For $remote_addr`,
`X-Forwarded-Proto $scheme`, `X-Real-IP $remote_addr`. **Trust policy: the
edge does not trust client-supplied forwarding headers - it OVERWRITES
them** with what it observed. (Verified by the harness: a probe-supplied
`X-Forwarded-For: 1.2.3.4` does not survive to the origin.)

### Body size (0C.2, EC2)
Per-tenant `client_max_body_size` from the policy model (`max_body_size`,
default 1m), validated against the node capacity bound
(`NODE_MAX_BODY_SIZE = 10m`).

### Timeouts and origin failure (0C.3, EC3)
`proxy_connect_timeout 5s; proxy_send_timeout 30s; proxy_read_timeout 30s;`
per tenant vhost. Origin failure has a defined response:
`error_page 502 503 504 =502 @origin_failure` returning fixed JSON
(`{"error":"edge_origin_unavailable"}`). Alerting consumes the access-log
502/504 stream already shipped by promtail; a Prometheus alert rule on that
stream is a Phase 3 operations item.

### WebSocket upgrades (0C.4, EC4)
Upgrade negotiation is forwarded per tenant
(`map $http_upgrade $connection_upgrade` rendered once at http scope;
`Upgrade`/`Connection` headers proxied). **Inspection boundary: CRS
inspects the upgrade REQUEST itself (headers/body of the HTTP upgrade);
frames inside an established upgraded connection pass uninspected.** The
per-tenant position (allow upgrades or not) is a future tenant policy knob,
not a global constant.

### Caching (0C.5, EC5)
REFUSED for the first release: no proxy cache is configured; no
`proxy_cache` directive exists in generated vhosts. Revisit only with
tenant-scoped cache keys and per-tenant zones.

### TLS / compression / IPv6 (0C.6-0C.7)
The edge currently serves plain HTTP; the TLS floor (redirect, cipher
policy, HSTS, OCSP) belongs to Phase 3 and is explicitly deferred - the
generated vhosts carry `gzip off;` and no TLS listener today. IPv6:
deliberately no AAAA records / no `[::]:80` listener until Phase 3 makes a
dual-stack decision. DNS cutover/rollback procedure (0C.8) is an operations
document, tracked separately.

### Harness (0C.9)
`docker/test-origin` (std-lib HTTP server) records method, path, scheme,
Host, client address, forwarded headers, body size and upgrade negotiation
into a bounded ring; `GET /observations` reads it. The harness is used by
the docker tests (tests/test_proxy_harness.py for the record shape;
tests/test_proxy_correctness.py for the 0D claims, including that the edge
alone returns the defined 502 and the origin never sees refused requests).

## Consequences

- The edge is, for the first time, an actual reverse proxy: tenant selection
  by Host, explicit refusal of unknown hosts, observed forwarding of client
  identity, body-size and upgrade semantics.
- Every 0C/0D claim above is enforced by a docker test that OBSERVES the
  origin's record rather than by reading configuration (0D.3).
- The tenant policy model (ADR 0003) is now the single source for both
  ModSecurity rules files AND proxy vhosts - Phase 2 extends the model, it
  does not replace it.
- TLS remains deferred (Phase 3); no customer traffic before the Section 12
  readiness checks pass, including the TLS floor.
