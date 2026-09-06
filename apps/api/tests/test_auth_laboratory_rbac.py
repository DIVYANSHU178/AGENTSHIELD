"""
Tests for AgentShield Phase 14 Scenario Laboratory RBAC and Lockout Protection.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.identity.authentication import get_auth_service
from app.security.models.utils import generate_uuid


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_tokens():
    auth_svc = get_auth_service()
    admin_sess = auth_svc.authenticate("admin", "AdminPass123!")
    rev_sess = auth_svc.authenticate("security_lead", "ReviewerPass123!")
    ops_sess = auth_svc.authenticate("ops_user", "OperatorPass123!")
    viewer_sess = auth_svc.authenticate("viewer_user", "ViewerPass123!")
    return {
        "admin": admin_sess.session_id,
        "reviewer": rev_sess.session_id,
        "operator": ops_sess.session_id,
        "viewer": viewer_sess.session_id,
    }


def test_operator_and_reviewer_can_run_laboratory_scenarios(client, auth_tokens):
    headers = {"Authorization": f"Bearer {auth_tokens['operator']}"}
    req_id = f"lab-test-ops-{generate_uuid()[:8]}"
    resp = client.post(
        "/api/v1/dev/laboratory/run",
        json={"scenario_id": "ALLOW_CLEAN", "request_id": req_id},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "ALLOW_CLEAN"
    assert data["passed"] is True


def test_viewer_is_denied_from_running_scenarios(client, auth_tokens):
    headers = {"Authorization": f"Bearer {auth_tokens['viewer']}"}
    req_id = f"lab-test-viewer-{generate_uuid()[:8]}"
    resp = client.post(
        "/api/v1/dev/laboratory/run",
        json={"scenario_id": "ALLOW_CLEAN", "request_id": req_id},
        headers=headers,
    )
    assert resp.status_code == 403
    assert "not authorized" in resp.json()["detail"].lower()
