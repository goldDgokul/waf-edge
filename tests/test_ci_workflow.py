"""Regression tests for GitHub Actions behavior."""

from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"


@pytest.mark.structural
def test_codecov_is_single_lane_and_non_blocking():
    """An external Codecov outage must not cancel tested Python lanes."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["test"]["steps"]
    upload = next(step for step in steps if step.get("name") == "Upload coverage to Codecov")

    assert upload.get("if") == "matrix.python-version == '3.10'", (
        "coverage is uploaded from every Python matrix lane, multiplying tokenless "
        "Codecov requests and making rate limits more likely"
    )
    assert upload.get("with", {}).get("fail_ci_if_error") is False, (
        "an optional Codecov reporting outage still fails the tested job, cancels "
        "the remaining matrix lanes, and skips docker-test"
    )


@pytest.mark.structural
def test_docker_job_uses_compose_v2_for_start_and_cleanup():
    """GitHub's runner provides `docker compose`, not legacy `docker-compose`."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["docker-test"]["steps"]
    run_commands = "\n".join(step.get("run", "") for step in steps)

    assert "docker-compose" not in run_commands, (
        "the docker job still calls the missing legacy docker-compose executable"
    )
    assert "docker compose up -d redis" in run_commands, (
        "the docker job does not start Redis through the Compose v2 plugin"
    )
    assert "docker compose down -v" in run_commands, (
        "cleanup does not use the same available Compose v2 plugin"
    )
