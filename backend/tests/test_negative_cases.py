"""
Negative & Failure Mode Unit Tests for RansomShield (Section 39)

Verifies graceful handling of:
- RBAC permission denials (VIEWER -> 403)
- Invalid JWT authentication (401)
- Decoy token isolation (403)
- PID reuse detection failure
- SHAP invocation on unsupported model types (IsolationForest)
- Report verification failure on missing records
"""

import pytest
from fastapi.testclient import TestClient
from backend.api.main import app
from backend.security.deception import create_access_token
from backend.modules.process_identity import validate_process_identity, IDENTITY_MISMATCH
from backend.ml.evaluation import MLEvaluator
from sklearn.ensemble import IsolationForest

client = TestClient(app)

def test_viewer_kill_process_forbidden():
    viewer_token = create_access_token({"sub": "viewer_user", "role": "VIEWER", "session_type": "PRODUCTION"})
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.post("/api/process/9999/kill", headers=headers)
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]

def test_invalid_jwt_unauthorized():
    headers = {"Authorization": "Bearer invalid.jwt.token.string"}
    response = client.get("/api/endpoints", headers=headers)
    assert response.status_code == 401

def test_decoy_session_isolation():
    decoy_token = create_access_token({"sub": "attacker", "role": "VIEWER", "session_type": "DECOY"})
    headers = {"Authorization": f"Bearer {decoy_token}"}
    response = client.get("/api/endpoints", headers=headers)
    assert response.status_code == 403
    assert "Decoy session tokens are strictly isolated" in response.json()["detail"]

def test_pid_reuse_guard_mismatch():
    import os, time
    current_pid = os.getpid()
    recorded_creation_time = time.time() - 100.0 # 100s in past
    status_code, details = validate_process_identity(current_pid, recorded_creation_time)
    assert status_code == IDENTITY_MISMATCH
    assert "PID REUSE DETECTED" in details["reason"]

def test_unsupported_model_shap():
    iso_model = IsolationForest()
    res = MLEvaluator.calculate_shap_values(iso_model, [1.0, 2.0, 3.0])
    assert res["status"] == "UNSUPPORTED_MODEL_TYPE"
    assert "ONLY for supervised classifiers" in res["message"]

def test_missing_report_verification():
    admin_token = create_access_token({"sub": "admin", "role": "ADMIN", "session_type": "PRODUCTION"})
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post("/api/reports/verify/non_existent_report_id", headers=headers)
    assert response.status_code == 404
