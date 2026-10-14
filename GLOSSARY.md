# GLOSSARY.md

The vocabulary of this project. Terms here are load-bearing: several of them are
commonly confused, and the confusion changes what gets built.

**Rule: when naming a concept in an issue, a test, a commit, or a design
document, use the term as defined here.** If a term you need is missing, that is
a signal — either you are inventing language this project does not use, or there
is a real gap worth recording.

---

## The product

**edge**
Our own nginx instances, hosted by us, sitting in front of a customer's server.
The edge is the only part of the customer's request path that we operate. It is
what "hosted edge" refers to throughout the plan.

**origin** (also: **customer origin**)
The customer's own server, which we forward traffic to. The origin belongs to the
customer; we never host it and never store its data. The plan's phrase is *"we
operate the edge, each customer keeps their own server."*

**hosted edge model**
The product shape: we host nginx in front of the customer's origin, terminate
TLS for their domain, inspect traffic, and forward it on. This is distinct from
the older **rule-push model** (below). The distinction matters because the code
was written for the rule-push model and the product is the hosted edge.

**rule-push model** (also: **agent mode**)
The model the code was originally written for: our control plane SSHes into a
server and pushes nginx rules to it, with no traffic passing through us. Retained
only as an optional agent; **it is not the product.**

**control plane**
Our API plus its data layer: tenants, users, nodes, rules, certificates, audit.
Distinct from the **edge**, which faces the internet. Where the control plane
runs is a recorded open decision.

**tenant**
A customer, as represented inside our platform. A tenant is a *row* in our data
model; a customer is the *organisation* it stands for. Every record is
tenant-scoped.

**isolation contract**
The published promise that tenants share infrastructure but cannot reach each
other's data, rules, logs or certificates. This is a **tested property**, not a
description: it is verified by attempting to cross the boundary.

---

## Traffic and protection

**in-line**
Blocking that happens *while the request is in flight*. nginx evaluates loaded
rules before the request reaches the origin; a match returns 403 immediately.
This is the only thing that actually stops an attack.

**out-of-band**
Work that happens *after the request has been served* — reading logs, detecting
patterns, generating rules. Out-of-band work cannot block the request that
triggered it. Detection and learning are out-of-band; **blocking is in-line.**

**the loop**
The full protection cycle: request arrives → nginx checks *loaded* rules →
allowed or blocked → request logged → background process reads logs → pattern
detected → **new rule written → pushed to the edge → nginx reloads**. The final
step is the fragile one and is where the critical defect lives.

**first occurrence gets through**
A consequence of the loop: a pattern not yet seen is not yet blocked. The first
instance of a new attack reaches the origin; repeats are blocked once the rule
lands. This is a property to state honestly, not a bug to hide.

**rule**
A structured object (type, condition, action, scope, expiry, tenant) that our
generator renders into nginx configuration. **Arbitrary nginx snippets are never
accepted as rules.**

**rule type**
The four kinds the generator emits: `block_ip` (`deny`), `rate_limit`
(`limit_req`), `block_url_pattern` and `block_user_agent` (both `if`). Two of
these four are **invalid where they are written** — see the critical defect.

**inspection scope**
What is actually examined: currently the URL and query string only. **Bodies,
headers and cookies are not inspected.** Any claim about protection must state
the scope, because the gaps are real.

---

## nginx concepts that are commonly confused

**reverse proxy**
Sits in front of *servers*, receives client requests, and forwards them to the
real server. **This is what our edge is.** The customer's application sees a
request that arrived via us.

**forward proxy**
Sits in front of *clients*, hiding them from the internet. **Not us.** No part of
this product is a forward proxy.

**load balancer**
Spreads traffic across *several copies of the same server*. **We do not do
this yet.** Load balancing is one function a reverse proxy *can* perform; it is
not what we are doing, and describing the edge as a load balancer implies
failover guarantees that a single-VM pilot cannot make.

**server block / vhost**
An nginx `server {}` block. **One per tenant**, selected by hostname. The
mechanism that keeps one tenant's traffic away from another's rules.

**server_name**
The nginx directive that binds a vhost to hostnames. **This is the tenant
isolation mechanism** — it is how nginx decides which tenant a request belongs
to.

**SNI** (Server Name Indication)
How a client tells the server which hostname it wants *during the TLS
handshake*, before any HTTP is sent. It is what lets one IP serve many
certificates. A mismatch between SNI and the `Host` header is a confusion attack
(the plan's T11).

**directive context**
Where in the config tree a directive may legally appear: `http`, `server` or
`location`. **`if` is valid only in `server` and `location`.** A directive used
in the wrong context is rejected by nginx with `[emerg]`.

**`map`**
A directive valid in the `http` context, used to compute a variable from
`$request_uri`, `$http_user_agent` and similar. The existing static rule file
(`basic.conf`) uses it. **It is the safe technique for rules at `http` scope**,
where `if` cannot be used.

**`nginx -t`**
The configuration test. The only reliable way to know a candidate config is
valid. **Textual validation is not a substitute** — that is precisely how the
critical defect reached production.

**reload vs restart**
`nginx -s reload` re-reads configuration without dropping existing connections.
**An invalid configuration does not merely fail to apply — it prevents a reload
*and* a restart.** That is why an invalid rule is an outage, not a missed
protection.

---

## TLS and what we can see

**TLS termination**
Ending the encrypted connection at our edge and speaking plain HTTP to the
origin. **We do this, and it is mandatory**: a WAF cannot inspect traffic it
cannot read. The consequence we must own is that **customer traffic is readable
in plain text on our edge** — hence the insider-access policy.

**pass-through** (rejected alternative)
Forwarding the still-encrypted stream to the origin to decrypt it there. Better
for confidentiality in general, **but incompatible with a WAF**, so it is not
available to us. Recorded so the choice is visible rather than accidental.

**origin bypass**
A request that reaches the customer's origin *without* passing through our edge,
making the edge and its rules pointless. Requires an onboarding requirement: the
origin must not be publicly reachable on the same hostname.

---

## Findings and status labels

**critical defect** (also: **the context bug**)
Generated `block_url_pattern` and `block_user_agent` rules emit `if (...)`,
which nginx rejects inside the `http {}` block where the rule file is included.
The server keeps serving but **can no longer reload or restart** — on a customer
server, an outage caused by our product.

**unreachable path**
The dispatcher defect: `_deploy_via_file()` returns success unconditionally, so
the validating SSH path — which backs up, runs `nginx -t`, reloads, verifies and
rolls back — **is never executed.**

**staged** vs **active**
A candidate config written somewhere on disk (**staged**) versus the
configuration nginx has actually loaded (**active**). The two must never be
reported as the same thing.

**[OBSERVED] / [DECIDED] / [PROPOSED] / [OPEN]**
The status labels used throughout the build plan. Observed in code or reproduced
on the running system; decided by the CEO; a technical recommendation not yet
approved; awaiting a decision that cannot be answered from the code.
