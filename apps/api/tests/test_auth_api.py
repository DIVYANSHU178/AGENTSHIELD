"""
Tests for AgentShield Phase 14 Auth REST API Endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.models.utils import generate_uuid


@pytest.fixture
def client():
    return TestClient(app)


def test_api_login_success(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["username"] == "admin"
    assert "ADMIN" in data["roles"]


def test_api_login_failure(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "BadPassword"})
    assert resp.status_code == 401


def test_api_me_endpoint(client):
    # 1. Login
    login_resp = client.post("/api/v1/auth/login", json={"username": "security_lead", "password": "ReviewerPass123!"})
    token = login_resp.json()["session_id"]

    # 2. Query /me
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "security_lead"
    assert "SECURITY_REVIEWER" in me_data["roles"]


def test_api_logout_endpoint(client):
    # 1. Login
    login_resp = client.post("/api/v1/auth/login", json={"username": "ops_user", "password": "OperatorPass123!"})
    token = login_resp.json()["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Verify active
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    # 3. Logout
    logout_resp = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_resp.status_code == 200
    assert logout_resp.json()["revoked"] is True

    # 4. Verify no longer active
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_api_authorize_check_endpoint(client):
    # Login as reviewer
    login_resp = client.post("/api/v1/auth/login", json={"username": "security_lead", "password": "ReviewerPass123!"})
    token = login_resp.json()["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Check RESOLVE_APPROVALS -> Allowed
    r1 = client.post("/api/v1/auth/authorize", json={"permission": "RESOLVE_APPROVALS"}, headers=headers)
    assert r1.status_code == 200
    assert r1.json()["allowed"] is True

    # Check MANAGE_IDENTITIES -> Denied
    r2 = client.post("/api/v1/auth/authorize", json={"permission": "MANAGE_IDENTITIES"}, headers=headers)
    assert r2.status_code == 200
    assert r2.json()["allowed"] is False


def test_api_identity_administration_crud(client):
    # Login as admin
    login_resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    admin_token = login_resp.json()["session_id"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create new identity
    new_uname = f"test_user_{generate_uuid()[:6]}"
    create_resp = client.post(
        "/api/v1/auth/identities",
        json={
            "username": new_uname,
            "password": "NewUserPassword123!",
            "display_name": "Test User",
            "roles": ["VIEWER"],
            "email": f"{new_uname}@test.local",
        },
        headers=admin_headers,
    )
    assert create_resp.status_code == 201
    new_user = create_resp.json()
    user_id = new_user["user_id"]

    # 2. Update roles to OPERATOR
    role_resp = client.post(
        f"/api/v1/auth/identities/{user_id}/roles",
        json={"roles": ["OPERATOR"]},
        headers=admin_headers,
    )
    assert role_resp.status_code == 200
    assert "OPERATOR" in role_resp.json()["roles"]

    # 3. Disable user
    dis_resp = client.post(f"/api/v1/auth/identities/{user_id}/disable", headers=admin_headers)
    assert dis_resp.status_code == 200
    assert dis_resp.json()["is_active"] is False
