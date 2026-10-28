# Edge Protection Measurement (CRS Baseline)

Plan v7.5 0B.5: report precision, recall / false negatives, false-positive
rate and latency / throughput per class and placement. Include poor
results. No broad protection claim without these numbers.

## What was measured

Every entry of the labeled edge corpus (`src/edge_corpus.py`) sent as
**literal wire bytes** (raw sockets, no HTTP client re-encoding) to a
throwaway container running the **shipped node image** with the
repository's real configuration mounted compose-identically. The corpus is
the same data the regression gate (`tests/test_edge_corpus.py`) asserts,
so the published numbers and the release gate cannot drift apart.

Measurement: 2026-10-28, after the 0B.2 slice (ADR 0002 CRS wiring +
njs content handlers).

## Results

| class | total | blocked | missed | recall | latency p50/p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| sensitive-file | 2 | 2 | none | 100% | 12.5 / 21.0 |
| sqli | 4 | 4 | none | 100% | 10.4 / 29.7 |
| traversal | 1 | 1 | none | 100% | 10.1 / 10.1 |
| xss | 6 | 6 | none | 100% | 4.6 / 23.3 |
| legitimate (safe) | 8 | 0 | none | false positive rate 0% | 4.0 / 25.5 |

- overall recall: 100% (13 labeled attacks)
- overall precision: 100%
- per placement: crs 12/12 blocked, static-extension-map 1/1 blocked
- environment: waf-corpus-node image, throwaway container on 127.0.0.1:63637, Windows 11 Docker Desktop, single sequential client, measured 2026-10-28
- sequential throughput on GET /: 151.1 req/s (30 requests)
- limitations: the corpus is a small, hand-labeled set (13 attacks / 8 safe requests); it pins known regressions and measured bypasses, it is NOT a broad protection claim; latency and throughput are one-container figures from the measurement environment, not production numbers.

## What each number means

- **Recall** is the share of labeled attacks the shipped node blocked at
  the corpus's expected status. A miss is listed by entry id.
- **False-positive rate** is the share of legitimate near-match requests
  that the node blocked. All safe entries target real origin endpoints, so
  an origin 404 can never be miscounted as a WAF decision.
- **Precision** is blocked-attacks / total-blocks: if the node blocked a
  legitimate request, precision drops below 100%.
- **Placement** is which mechanism did the blocking: CRS phase 2
  (ModSecurity, OWASP CRS 4.30.0) or the static extension map (rewrite
  phase, before CRS). The 8 legitimate entries are served by the njs
  content handlers (content phase, after CRS evaluation).

## Poor results and known limits

These results are deliberately published with their weaknesses:

1. **Small hand-labeled corpus.** 13 attacks / 8 safe requests. It pins
   measured regressions and former bypasses; it does NOT establish
   protection against classes or encodings absent from the corpus
   (e.g. log4j/RCE payloads, multipart bodies, HTTP/2, obfuscated
   payload variants).
2. **Recall is measured only on classes present in the corpus.** sqli,
   xss, traversal and sensitive-file are covered; every other attack
   class has an unknown recall.
3. **Precision is measured only against 8 legitimate requests.** Real
   traffic will contain near-matches the corpus does not model; production
   adoption (ADR 0002) stays gated on exclusion tuning against
   representative traffic, not on this table.
4. **Latency/throughput are single-container figures** on a Windows
   Docker Desktop host with one sequential client and `Connection: close`
   per request; they say nothing about production load behaviour.
5. **No origin round-trip measured.** All requests terminate at the edge
   (canned responses or blocks); origin-side latency composition is
   unknown.

## Reproducing

```
python -m pytest tests/test_edge_measurement.py -m docker
```

The docker test re-measures the shipped node and compares every per-class
metric against this page; if the corpus or engine behaviour changes, the
commit must regenerate this report or the test fails.
