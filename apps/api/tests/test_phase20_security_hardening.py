"""
Verification and Adversarial Test Suite for Phase 20 Security Hardening.
Covers:
1. Tool and Policy management RBAC (P0)
2. RealHttpTool DNS rebinding and redirect SSRF defense (P2)
3. Approval fingerprint verification and tampering prevention (P1)
4. Approval execution concurrency race / atomic claim (P1)
5. CSRF defense middleware double-submit cookie validation (P2)
"""

import os
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.config.settings import settings
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.identity.dependencies import get_current_user, get_current_user_optional
from app.security.execution.tools.real_http import RealHttpTool
from app.security.approval.contracts import (
    ApprovalRequest,
    ApprovalStatus,
    ReviewerIdentity,
)
from app.security.approval.service import get_approval_service
from app.security.approval.errors import (
    ApprovalTamperingError,
    InvalidApprovalStateTransitionError,
)
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecision,
    SecurityDecisionType,
    RiskAssessment,
    ThreatReport,
    Severity,
)
from app.security.gateway import SecurityEvaluationResult


@pytest.fixture
def unauth_client():
    """Client with no authentication headers or dependency overrides."""
    return TestClient(app)


@pytest.fixture
def viewer_client():
    viewer_user = UserIdentity(
        user_id="usr_viewer_01",
        username="viewer_test",
        display_name="Viewer Test",
        email="viewer@test.local",
        roles=[Role.VIEWER],
        permissions=[Permission.VIEW_OPERATIONS, Permission.VIEW_AUDIT],
    )
    app.dependency_overrides[get_current_user] = lambda: viewer_user
    app.dependency_overrides[get_current_user_optional] = lambda: viewer_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_user_optional, None)


@pytest.fixture
def admin_client():
    admin_user = UserIdentity(
        user_id="usr_admin_01",
        username="admin_test",
        display_name="Admin Test",
        email="admin@test.local",
        roles=[Role.ADMIN],
        permissions=[p for p in Permission],
    )
    app.dependency_overrides[get_current_user] = lambda: admin_user
    app.dependency_overrides[get_current_user_optional] = lambda: admin_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_user_optional, None)


# =============================================================================
# 1. TOOL & POLICY MANAGEMENT RBAC (P0)
# =============================================================================

def test_tool_endpoints_unauthenticated_rejected(unauth_client):
    assert unauth_client.get("/api/v1/tools").status_code == 401
    assert unauth_client.get("/api/v1/tools/calculator").status_code == 401
    assert unauth_client.post("/api/v1/tools", json={
        "tool_id": "test_t1",
        "name": "T1",
        "category": "TEST",
        "description": "desc",
    }).status_code == 401
    assert unauth_client.delete("/api/v1/tools/test_t1").status_code == 401


def test_policy_endpoints_unauthenticated_rejected(unauth_client):
    assert unauth_client.get("/api/v1/policies").status_code == 401
    assert unauth_client.get("/api/v1/policies/p1").status_code == 401
    assert unauth_client.post("/api/v1/policies", json={
        "policy_id": "p_test",
        "name": "P Test",
        "description": "desc",
        "rule_type": "DEFAULT",
        "priority": 10,
    }).status_code == 401
    assert unauth_client.delete("/api/v1/policies/p_test").status_code == 401


def test_viewer_cannot_mutate_tools_or_policies(viewer_client):
    # Viewer can read operations/tools/policies
    assert viewer_client.get("/api/v1/tools").status_code == 200
    assert viewer_client.get("/api/v1/policies").status_code == 200

    # Viewer cannot register tools
    tool_resp = viewer_client.post("/api/v1/tools", json={
        "tool_id": "viewer_tool",
        "name": "Viewer Tool",
        "category": "TEST",
        "description": "desc",
    })
    assert tool_resp.status_code == 403

    # Viewer cannot delete tools
    assert viewer_client.delete("/api/v1/tools/calculator").status_code == 403

    # Viewer cannot create policies
    pol_resp = viewer_client.post("/api/v1/policies", json={
        "policy_id": "viewer_policy",
        "name": "Viewer Policy",
        "description": "desc",
        "rule_type": "DEFAULT",
        "priority": 10,
    })
    assert pol_resp.status_code == 403

    # Viewer cannot delete policies
    assert viewer_client.delete("/api/v1/policies/policy.block.high_risk").status_code == 403


def test_admin_can_manage_tools_and_policies(admin_client):
    tool_id = f"admin_tool_{uuid.uuid4().hex[:6]}"
    resp_tool = admin_client.post("/api/v1/tools", json={
        "tool_id": tool_id,
        "name": "Admin Tool",
        "category": "CUSTOM",
        "description": "Registered via admin",
    })
    assert resp_tool.status_code == 201
    assert resp_tool.json()["tool_id"] == tool_id

    # Admin delete tool
    del_tool = admin_client.delete(f"/api/v1/tools/{tool_id}")
    assert del_tool.status_code == 200

    policy_id = f"admin_pol_{uuid.uuid4().hex[:6]}"
    resp_pol = admin_client.post("/api/v1/policies", json={
        "policy_id": policy_id,
        "name": "Admin Policy",
        "description": "Created via admin",
        "rule_type": "BLOCK",
        "priority": 80,
    })
    assert resp_pol.status_code == 201
    assert resp_pol.json()["policy_id"] == policy_id

    del_pol = admin_client.delete(f"/api/v1/policies/{policy_id}")
    assert del_pol.status_code == 200


# =============================================================================
# 2. REAL HTTP TOOL SSRF & DNS REBINDING DEFENSE (P2)
# =============================================================================

def test_real_http_blocks_ssrf_destinations():
    tool = RealHttpTool()

    # Loopback targets
    with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked request|Private"):
        tool.execute({"url": "http://127.0.0.1:8000/api/v1/secret"})

    with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked request|Private"):
        tool.execute({"url": "http://localhost:8000/status"})

    # RFC1918 Private targets
    with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked request|Private"):
        tool.execute({"url": "http://10.0.0.1/admin"})

    with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked request|Private"):
        tool.execute({"url": "http://192.168.1.1/config"})

    with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked request|Private"):
        tool.execute({"url": "http://172.16.0.1/status"})

    # Cloud Metadata Service
    with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked request|Private"):
        tool.execute({"url": "http://169.254.169.254/latest/meta-data/"})


def test_real_http_blocks_redirect_to_ssrf():
    tool = RealHttpTool()

    # Mock DNS resolution for initial public domain
    with patch("socket.getaddrinfo") as mock_dns:
        # First call resolves public IP 93.184.216.34 (example.com)
        # Second call for redirect resolves 127.0.0.1
        mock_dns.side_effect = [
            [(2, 1, 6, "", ("93.184.216.34", 80))],
            [(2, 1, 6, "", ("127.0.0.1", 80))],
        ]
        with patch("http.client.HTTPConnection") as mock_conn:
            instance = mock_conn.return_value
            # Initial response is a 302 redirect to localhost
            mock_resp = type("MockResponse", (), {
                "status": 302,
                "getheader": lambda self, name, default=None: "http://127.0.0.1:8000/admin" if str(name).lower() == "location" else default,
                "read": lambda self, n=None: b"",
            })()
            instance.getresponse.return_value = mock_resp

            with pytest.raises((PermissionError, ValueError), match="SSRF Protection|Blocked"):
                tool.execute({"url": "http://example.com/redirect", "follow_redirects": True})


# =============================================================================
# 3. APPROVAL FINGERPRINT TAMPERING & CONCURRENCY (P1)
# =============================================================================

def _create_test_approval(tool_name: str = "calculator", params: dict = None):
    svc = get_approval_service()
    req_id = f"req-{uuid.uuid4().hex[:8]}"
    req = ToolRequest(
        request_id=req_id,
        agent=AgentIdentity(name="SecAgent"),
        target=tool_name,
        tool_name=tool_name,
        tool_category=ToolCategory.OTHER,
        action=ActionType.EXECUTE,
        parameters=params or {"expression": "2 + 2"},
    )
    eval_res = SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(
            request_id=req_id,
            signals=[],
            overall_severity=Severity.MEDIUM,
            summary="Review required by policy",
        ),
        risk_assessment=RiskAssessment(
            request_id=req_id,
            risk_score=50.0,
            severity=Severity.MEDIUM,
            rationale="Test",
        ),
        decision=SecurityDecision(
            request_id=req_id,
            decision=SecurityDecisionType.REQUIRE_APPROVAL,
            reason="Requires approval",
        ),
    )
    return svc.create_approval(eval_res, ttl_seconds=300.0)


def test_approval_tampered_fingerprint_rejected():
    from app.models.models import ApprovalRequestModel
    svc = get_approval_service()
    approval = _create_test_approval("calculator", {"expression": "50 * 2"})

    # Directly tamper with the database row's canonical fingerprint (simulating DB tampering attack)
    if svc._repository is not None:
        from sqlalchemy import select
        session = svc._repository._get_session()
        row = session.scalar(select(ApprovalRequestModel).where(ApprovalRequestModel.approval_id == approval.approval_id))
        row.request_fingerprint = "a" * 64
        session.commit()
        session.close()
    else:
        tampered = approval.model_copy(update={"request_fingerprint": "a" * 64})
        svc._approvals[approval.approval_id] = tampered

    reviewer = ReviewerIdentity(reviewer_id="rev-01", reviewer_name="Reviewer", role="ADMIN")
    with pytest.raises(ApprovalTamperingError, match="Request fingerprint tampering detected"):
        svc.approve(approval.approval_id, reviewer=reviewer, reason="Approve tampered")


def test_approval_atomic_claim_race_prevention():
    svc = get_approval_service()
    approval = _create_test_approval("calculator", {"expression": "100 / 4"})

    reviewer = ReviewerIdentity(reviewer_id="rev-01", reviewer_name="Reviewer", role="ADMIN")

    # First approve succeeds and transitions to APPROVED (after claiming)
    res = svc.approve(approval.approval_id, reviewer=reviewer, reason="First execution")
    assert res.status == ApprovalStatus.APPROVED

    # Subsequent approval call on same approval fails
    with pytest.raises(InvalidApprovalStateTransitionError):
        svc.approve(approval.approval_id, reviewer=reviewer, reason="Second duplicate execution")


# =============================================================================
# 4. CSRF DEFENSE MIDDLEWARE (P2)
# =============================================================================

def test_csrf_defense_on_cookie_session(unauth_client):
    # Mutating request with cookie session but no X-CSRF-Token -> 403
    unauth_client.cookies.set("session_id", "sess_fake_12345")
    resp_missing = unauth_client.post("/api/v1/auth/identities", json={
        "username": "attacker_created",
        "password": "Password123!",
        "display_name": "Attacker",
        "roles": ["ADMIN"],
    })
    assert resp_missing.status_code == 403
    assert "CSRF validation failed" in resp_missing.json()["detail"]

    # Mismatched CSRF token -> 403
    unauth_client.cookies.set("csrf_token", "valid_csrf_token_abc")
    resp_mismatch = unauth_client.post(
        "/api/v1/auth/identities",
        headers={"X-CSRF-Token": "wrong_csrf_token_xyz"},
        json={"username": "attacker_created", "password": "Password123!"},
    )
    assert resp_mismatch.status_code == 403
    assert "CSRF validation failed" in resp_mismatch.json()["detail"]

    # Bearer token request is exempt from CSRF
    unauth_client.cookies.clear()
    resp_bearer = unauth_client.get(
        "/api/v1/tools",
        headers={"Authorization": "Bearer invalid_bearer"},
    )
    # Reaches auth validation (401 because invalid token), not CSRF 403
    assert resp_bearer.status_code == 401
