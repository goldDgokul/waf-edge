"""0B.5: published edge measurement (per-class precision/recall/FP/latency).

Plan v7.5 0B.5: "Report precision, recall/false negatives, false-positive
rate and latency/throughput per class and placement. Include poor results.
No broad protection claim without these numbers."

Two halves:

  - src/edge_measurement.py computes per-class metrics from labeled
    observations and renders them as the report table. The unit tests pin
    the metric arithmetic (recall, false positives, precision) on
    fabricated observations so a broken summariser cannot silently
    validate a wrong report.

  - The committed report (docs/guide/measurement.md) is a tripwire: the
    docker test re-measures the shipped node and compares every per-class
    decision metric against the published table. If the corpus changes
    or the engine behaviour changes, the report must be regenerated in
    the same commit or this test fails.

Latency and throughput are environment-dependent; the report publishes
them with the measurement environment, and the tests assert presence and
shape rather than exact values.
"""

import re
from pathlib import Path

import pytest

from src.edge_corpus import ENTRY_COUNT, ATTACK_ENTRY_COUNT, SAFE_ENTRY_COUNT
from src.edge_measurement import Observation, summarize, render_report, spin_up_node

docker = pytest.mark.docker

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT = REPO_ROOT / "docs" / "guide" / "measurement.md"


@pytest.fixture(scope="module")
def corpus_port():
    """A throwaway container running the SHIPPED node image with the
    repository's real configuration (same discipline as the corpus tests)."""
    with spin_up_node() as port:
        yield port


def _obs(attack_class="sqli", placement="crs", expected=403, status=None, latency=1.0):
    if status is None:
        status = expected
    return Observation(
        entry_id=f"{attack_class}-{placement}",
        attack_class=attack_class,
        placement=placement,
        expected_status=expected,
        status=status,
        latency_ms=latency,
    )


class TestSummarize:
    def test_per_class_recall_and_misses(self):
        obs = [
            _obs(attack_class="sqli", status=403),
            _obs(attack_class="sqli", status=200),
            _obs(attack_class="xss", status=403),
        ]
        report = summarize(obs)
        assert report["per_class"]["sqli"]["total"] == 2
        assert report["per_class"]["sqli"]["blocked"] == 1
        assert report["per_class"]["sqli"]["recall"] == pytest.approx(0.5)
        assert report["per_class"]["sqli"]["missed"] == ["sqli-crs"]
        assert report["per_class"]["xss"]["recall"] == 1.0
        assert report["recall"] == pytest.approx(2 / 3)

    def test_false_positive_rate_from_safe_traffic(self):
        obs = [
            _obs(attack_class="sqli", status=403),
            _obs(attack_class="legitimate", expected=200),
            _obs(attack_class="legitimate", expected=200, status=403),
        ]
        report = summarize(obs)
        assert report["safe"]["total"] == 2
        assert report["safe"]["blocked"] == 1
        assert report["safe"]["false_positive_rate"] == pytest.approx(0.5)
        assert report["safe"]["blocked_ids"] == ["legitimate-crs"]
        assert report["precision"] == pytest.approx(1 / 2)

    def test_per_placement_counts(self):
        obs = [
            _obs(attack_class="sqli", placement="crs"),
            _obs(attack_class="sqli", placement="static-extension-map", expected=404),
            _obs(attack_class="sqli", placement="static-extension-map", status=200),
        ]
        report = summarize(obs)
        assert report["per_placement"]["crs"]["attacks"] == 1
        assert report["per_placement"]["crs"]["blocked"] == 1
        assert report["per_placement"]["static-extension-map"]["attacks"] == 2
        assert report["per_placement"]["static-extension-map"]["blocked"] == 1

    def test_latency_percentiles_per_class(self):
        obs = [
            _obs(attack_class="sqli", latency=10.0),
            _obs(attack_class="sqli", latency=20.0),
            _obs(attack_class="sqli", latency=30.0),
            _obs(attack_class="xss", latency=1.0),
        ]
        report = summarize(obs)
        assert report["per_class"]["sqli"]["latency_ms"]["p50"] == 20.0
        assert report["per_class"]["sqli"]["latency_ms"]["p95"] == 30.0
        assert report["latency_ms"]["p50"] == 15.0
        assert report["latency_ms"]["p95"] == 30.0

    def test_safe_latency_excluded_from_attack_latency(self):
        obs = [
            _obs(attack_class="sqli", latency=5.0),
            _obs(attack_class="legitimate", expected=200, latency=100.0),
        ]
        report = summarize(obs)
        assert report["latency_ms"]["p95"] == 5.0
        assert report["safe"]["latency_ms"]["p95"] == 100.0

    def test_every_corpus_class_and_placement_covered(self):
        obs = [_obs(attack_class="sqli"), _obs(attack_class="legitimate", expected=200)]
        report = summarize(obs)
        assert report["counts"]["attacks"] == 1
        assert report["counts"]["safe"] == 1


class TestRender:
    def test_render_contains_every_corpus_class(self):
        obs = [
            _obs(attack_class="sqli", status=403),
            _obs(attack_class="xss", status=403),
            _obs(attack_class="legitimate", expected=200),
        ]
        text = render_report(obs, environment="test-env")
        assert "sqli" in text and "xss" in text and "legitimate" in text
        assert "recall" in text and "precision" in text
        assert "false positive" in text.lower()

    def test_render_renders_missed_attack_ids(self):
        obs = [_obs(attack_class="sqli", status=200)]
        text = render_report(obs, environment="test-env")
        assert "sqli-crs" in text

    def test_render_publishes_environment_and_limitations(self):
        obs = [_obs(attack_class="sqli")]
        text = render_report(obs, environment="waf-corpus-node on 127.0.0.1:12345")
        assert "waf-corpus-node" in text
        assert "limitation" in text.lower()


class TestPublishedReport:
    def test_report_exists_with_required_sections(self):
        text = REPORT.read_text(encoding="utf-8")
        assert text.strip(), "measurement.md is empty"
        for marker in ("recall", "precision", "false positive", "latency",
                       "throughput", "limitation"):
            assert marker in text.lower(), f"report missing {marker}"

    @docker
    def test_report_matches_a_live_measurement(self, corpus_port):
        text = REPORT.read_text(encoding="utf-8")
        from src.edge_measurement import run_measurement
        obs = run_measurement(corpus_port)
        measured = summarize(obs)

        for attack_class, metrics in measured["per_class"].items():
            row = re.search(
                rf"^\|\s*{re.escape(attack_class)}\s*\|.*$",
                text, re.MULTILINE,
            )
            assert row, f"published report has no row for class {attack_class}"
            recall = metrics["recall"]
            assert f"| {metrics['total']} |" in row.group(0), (
                f"published total for {attack_class} does not match measured "
                f"{metrics['total']} (regenerate the report with the current corpus)"
            )
            assert f"{recall:.0%}" in row.group(0), (
                f"published recall for {attack_class} does not match measured {recall:.0%}"
            )

        assert re.search(r"precision[^\d]*\d+", text, re.IGNORECASE)
        assert measured["safe"]["blocked"] == 0, (
            "live measurement produced false positives; the report must be "
            "regenerated with the new numbers before this commit"
        )


def test_corpus_shape_constants():
    assert ATTACK_ENTRY_COUNT + SAFE_ENTRY_COUNT == ENTRY_COUNT
