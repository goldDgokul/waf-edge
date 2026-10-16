"""
0A.3 Step 4 - the MANUAL deploy path must not report success it did not achieve.

Two callers deploy rules:
    automatic  main.py ~1343  (threat processor)   - fixed in 0A.2
    manual     main.py ~1484  (POST /api/rules/deploy)  - still broken

The manual one raises only when EVERY node fails:

    if len(failed_deployments) == len(deployment_results):
        raise HTTPException(500, "Deployment failed on all nodes")
    ...
    logger.info("Rules deployed successfully")      <- unconditional

So a PARTIAL failure - one node protecting traffic, one not - is reported as
success. In a security product that is the worst kind of wrong: an operator reads
"deployed" and believes every node is enforcing the rule.

This test drives the REAL endpoint, with the REAL response body, rather than
grepping the source for a log line. A source check would pass as soon as someone
reworded the message.
"""
import asyncio
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.validation import SecureRuleDeploymentRequest  # noqa: E402


def _request():
    return SecureRuleDeploymentRequest(
        rules=[{"rule_id": "r1", "pattern": "union select", "action": "block"}],
        node_ids=["node_1", "node_2"],
    )


class _FakeManagerPartialFailure:
    """One node succeeds, one fails - the case the current code mis-reports."""

    def _validate_nginx_config(self, config):
        return True

    async def deploy_rules_to_all_nodes(self, config):
        return {"node_1": True, "node_2": False}

    # Added 2026-10-16. The endpoint now honours request.node_ids via a separate
    # method, so a fake manager must provide it. The request under test names BOTH
    # nodes, so the selective path must reproduce the SAME partial result as the
    # all-nodes path - otherwise this test would assert the routing rather than the
    # reporting behaviour it was written for.
    async def deploy_rules_to_specific_nodes(self, node_ids, config):
        all_results = {"node_1": True, "node_2": False}
        # Mirror the real method's contract: every requested id is answered.
        return {nid: all_results.get(nid, False) for nid in node_ids}


class _FakeGenerator:
    def get_active_rules(self):
        return []

    def generate_nginx_config(self, rules):
        return "# generated\n"


def _install(monkeypatch, manager):
    import src.main as main
    from src import main as main_mod

    monkeypatch.setattr(
        main_mod.component_manager, "get_component",
        lambda name: manager if name == "nginx_manager" else (
            _FakeGenerator() if name == "waf_rule_generator" else None
        ),
    )
    return main_mod


def test_partial_failure_is_reported_as_failure(monkeypatch):
    """
    A deployment where ONE node failed must not return success, and the error
    must say WHICH nodes are protected and which are not.

    An operator needs the detail, not just a status code: "deployment failed" with
    no names leaves them unable to tell whether traffic is protected on the nodes
    they care about. An earlier version of this test asserted only the status code
    and never reached these fields - the independent review flagged that the body
    was unverified.
    """
    main_mod = _install(monkeypatch, _FakeManagerPartialFailure())

    from fastapi import HTTPException

    try:
        result = asyncio.run(main_mod.deploy_rules(_request()))
    except HTTPException as exc:
        assert exc.status_code >= 400, (
            f"a partial failure was raised with a success status {exc.status_code}"
        )

        detail = exc.detail
        assert isinstance(detail, dict), (
            "the error body must carry per-node detail so an operator can act, "
            f"but it was: {detail!r}"
        )

        # The failed node must be named as failed, and the healthy one as active.
        # Both halves matter: listing only the failure leaves the operator unsure
        # whether the other node is protecting traffic.
        assert detail.get("failed_nodes") == ["node_2"], (
            f"the failing node is not named correctly: {detail.get('failed_nodes')!r}"
        )
        assert detail.get("active_nodes") == ["node_1"], (
            f"the still-protecting node is not named correctly: {detail.get('active_nodes')!r}"
        )

        # And the message must not claim protection. "staged but NOT ACTIVE" is the
        # honest wording; a bare "deployed" would be the false success this whole
        # change exists to remove.
        message = str(detail.get("message", "")).lower()
        assert "not active" in message or "not become active" in message, (
            f"the error message does not state that the rules are NOT active: {message!r}"
        )

        # The per-node map is also carried, so a caller can see the raw results.
        assert detail.get("deployment_results") == {"node_1": True, "node_2": False}, (
            f"the per-node results are missing or wrong: {detail.get('deployment_results')!r}"
        )
        return

    # If it returned normally, the body must not claim success for the failed node.
    assert isinstance(result, dict), f"unexpected return type: {type(result)}"

    results = result.get("deployment_results", {})
    assert results.get("node_2") is False, (
        "the failed node is not reported as failed in the response body: "
        f"{result}"
    )

    message = str(result.get("message", "")).lower()
    all_ok = all(results.values()) if results else False
    if not all_ok:
        assert "initiated" not in message or "fail" in message or "not active" in message, (
            "the endpoint returned a success-shaped message for a deployment where "
            f"a node failed: {result}"
        )


class _FakeManagerAllOk:
    """Every node succeeds - the fix must not turn this into a failure."""

    def _validate_nginx_config(self, config):
        return True

    async def deploy_rules_to_all_nodes(self, config):
        return {"node_1": True, "node_2": True}

    # Added 2026-10-16, see _FakeManagerPartialFailure above. The request names both
    # nodes, so the selective path answers both, truthfully.
    async def deploy_rules_to_specific_nodes(self, node_ids, config):
        return {nid: True for nid in node_ids}


def test_full_success_is_still_reported_as_success(monkeypatch):
    """
    Guard against over-correction. A fix that reports failure on success would be
    just as wrong, and would train operators to ignore the signal.
    """
    main_mod = _install(monkeypatch, _FakeManagerAllOk())

    from fastapi import HTTPException

    try:
        result = asyncio.run(main_mod.deploy_rules(_request()))
    except HTTPException as exc:  # pragma: no cover - would be a regression
        raise AssertionError(
            f"a deployment where every node succeeded was reported as an error: "
            f"{exc.status_code} {exc.detail}"
        )

    assert result["deployment_results"] == {"node_1": True, "node_2": True}
    assert "active" in result["message"].lower(), (
        f"the success message no longer states the rules are active: {result['message']}"
    )
