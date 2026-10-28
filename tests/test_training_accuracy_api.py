"""ML-3 (API level): /api/training/start must report the HELD-OUT evaluation
accuracy, never a formula on sample count.

Plan v7.5 ML-3: "/api/training/start calculates
`0.85 + sample_count/10000 * 0.1`, capped at 0.95, rather than returning
held-out prediction accuracy. Dataset size cannot substitute for precision,
recall, false-positive rate or false-negative rate."

The engine-level tests live in tests/test_ml_engine.py
(TestHeldOutEvaluation). This module pins the API contract:
 - with a held-out evaluation, model_accuracy IS that accuracy and the
   evaluation detail (test_samples, precision, recall) is exposed;
 - with NO held-out evaluation, no accuracy number is invented: the
   response reports null and does not touch the accuracy metric.
"""

import uuid
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from src.main import app, component_manager
from src.auth import auth_manager


@pytest.fixture(scope="module")
def operator_headers():
    """A real operator user + JWT through the real AuthManager."""
    username = f"ml3-operator-{uuid.uuid4().hex[:8]}"
    auth_manager.create_user(username, "pw-ml3-operator", ["operator"])
    token = auth_manager.create_jwt_token(username)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def client():
    return TestClient(app, base_url="http://localhost")


def _engine(last_evaluation):
    engine = Mock()
    engine.is_trained = True
    engine.last_evaluation = last_evaluation
    return engine


def _patch_components(engine):
    return patch.object(
        component_manager, "get_component",
        side_effect=lambda name: engine if name == "ml_engine" else None,
    )


def test_reports_heldout_accuracy_not_formula(client, operator_headers):
    engine = _engine({
        "accuracy": 0.916, "precision": 0.88, "recall": 0.87,
        "test_samples": 24,
        "classes": ["normal", "sql_injection", "xss_attack"],
    })
    with _patch_components(engine):
        response = client.post("/api/training/start", headers=operator_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["model_accuracy"] == 0.916
    assert data["evaluation"]["test_samples"] == 24
    assert data["evaluation"]["precision"] == 0.88


def test_without_evaluation_invents_no_accuracy(client, operator_headers):
    engine = _engine(None)
    with _patch_components(engine):
        response = client.post("/api/training/start", headers=operator_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["model_accuracy"] is None
    assert data["evaluation"] is None


def test_size_formula_is_gone_from_the_source():
    """Tripwire on the exact simulated formula from the audit finding."""
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "src" / "main.py").read_text(
        encoding="utf-8")
    assert "0.85 + (len(training_data) / 10000) * 0.1" not in source
    assert "last_evaluation" in source, (
        "training must source model_accuracy from the held-out evaluation"
    )
