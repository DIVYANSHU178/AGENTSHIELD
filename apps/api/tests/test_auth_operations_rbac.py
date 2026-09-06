"""
Tests for AgentShield Phase 14 Operations Console RBAC.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.identity.authentication import get_auth_service


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_tokens(client):
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


def test_viewer_has_read_access_to_operations(client, auth_tokens):
    headers = {"Authorization": f"Bearer {auth_tokens['viewer']}"}
    r1 = client.get("/api/v1/security/operations/overview", headers=headers)
    assert r1.status_code == 200

    r2 = client.get("/api/v1/security/operations/health", headers=headers)
    assert r2.status_code == 200

    r3 = client.get("/api/v1/security/operations/threats", headers=headers)
    assert r3.status_code == 200

    r4 = client.get("/api/v1/security/operations/decisions", headers=headers)
    assert r4.status_code == 200


def test_unauthenticated_or_invalid_token_rejected_on_protected_actions(client):
    # Invalid token -> 401
    bad_headers = {"Authorization": "Bearer invalid-token-12345"}
    r1 = client.get("/api/v1/auth/me", headers=bad_headers)
    assert r1.status_code == 401


def test_operations_control_endpoint_rbac(client, auth_tokens):
    headers_viewer = {"Authorization": f"Bearer {auth_tokens['viewer']}"}
    resp = client.post(
        "/api/v1/security/operations/control",
        json={"action": "READ_HEALTH"},
        headers=headers_viewer,
    )
    assert resp.status_code == 200
    assert resp.json()["success"] is True
