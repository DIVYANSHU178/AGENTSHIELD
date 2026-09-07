"""
Tests for AgentShield Phase 20 Approval-Execution Pipeline (SEC-03 Remediation).
Verifies:
1. Approval lifecycle state machine (PENDING -> APPROVED / REJECTED / CANCELLED / EXPIRED)
2. Terminal state enforcement and tamper-proof transitions
3. Real tool execution triggered upon approval resolution
4. Execution result persistence in ApprovalRepository
5. RBAC role enforcement (VIEWER role rejection)
6. REST API endpoints for retrieval, approval, rejection, and cancellation
7. Fingerprint verification and request binding validation
"""

import os
import pytest
from datetime import timedelta
from fastapi.testclient import TestClient

from app.main import app
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
from app.security.approval.contracts import (
    ApprovalStatus,
    ApprovalDecision,
    ReviewerIdentity,
    ApprovalRequest,
)
from app.security.approval.service import ApprovalService, get_approval_service, set_approval_service
from app.security.approval.policy import ApprovalPolicy
from app.security.approval.errors import (
    ApprovalNotFoundError,
    ApprovalExpiredError,
    InvalidApprovalStateTransitionError,
    ApprovalPolicyViolationError,
)
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.identity.errors import AuthorizationDeniedError
from app.security.persistence.approval_repository import ApprovalRepository
from app.security.audit.trail import SecurityAuditTrail
from app.security.models.utils import utc_now


def _make_eval_result(
    tool_name: str = "calculator",
    parameters: dict = None,
    action: ActionType = ActionType.EXECUTE,
    category: ToolCategory = ToolCategory.OTHER,
    decision_type: SecurityDecisionType = SecurityDecisionType.REQUIRE_APPROVAL,
    request_id: str = "req-test-app-001",
) -> SecurityEvaluationResult:
    req = ToolRequest(
        request_id=request_id,
        agent=AgentIdentity(name="AutonomousAgent-ApprovalTest"),
        tool_name=tool_name,
        tool_category=category,
        action=action,
        target="target-system",
        parameters=parameters or {},
    )
    return SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(
            request_id=req.request_id,
            signals=[],
            overall_severity=Severity.MEDIUM,
            summary="Review required by policy",
        ),
        risk_assessment=RiskAssessment(
            request_id=req.request_id,
            risk_score=50.0,
            severity=Severity.MEDIUM,
            rationale="Medium risk tool execution",
        ),
        decision=SecurityDecision(
            request_id=req.request_id,
            decision=decision_type,
            policy_id="pol-require-approval",
            reason="Action requires human authorization",
        ),
    )


@pytest.fixture
def clean_approval_service():
    audit = SecurityAuditTrail()
    repo = ApprovalRepository()
    repo.clear()
    service = ApprovalService(repository=repo, audit_trail=audit)
    old_service = get_approval_service()
    set_approval_service(service)
    yield service
    repo.clear()
    set_approval_service(old_service)


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Approval Creation & Policy Validation
# ---------------------------------------------------------------------------

def test_approval_lifecycle_create_pending(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "21 * 2"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    assert approval.approval_id is not None
    assert approval.status == ApprovalStatus.PENDING
    assert approval.tool_name == "calculator"
    assert approval.parameters == {"expression": "21 * 2"}
    assert approval.request_fingerprint is not None
    assert approval.resolution is None
    assert approval.execution_result is None


def test_approval_lifecycle_cannot_create_from_allow_decision(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "1 + 1"}, decision_type=SecurityDecisionType.ALLOW)
    with pytest.raises(ApprovalPolicyViolationError):
        clean_approval_service.create_approval(eval_res)


def test_approval_lifecycle_cannot_create_from_block_decision(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "1 + 1"}, decision_type=SecurityDecisionType.BLOCK)
    with pytest.raises(ApprovalPolicyViolationError):
        clean_approval_service.create_approval(eval_res)


# ---------------------------------------------------------------------------
# 2. State Machine Transitions
# ---------------------------------------------------------------------------

def test_approval_lifecycle_approve_transitions_to_approved(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "100 + 200"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    reviewer = ReviewerIdentity(reviewer_id="rev-001", reviewer_name="Alice SecOps", role="SECURITY_REVIEWER")
    resolved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Operation verified safe")

    assert resolved.status == ApprovalStatus.APPROVED
    assert resolved.resolution is not None
    assert resolved.resolution.decision == ApprovalDecision.APPROVE
    assert resolved.resolution.reviewer.reviewer_id == "rev-001"
    assert resolved.execution_result is not None
    assert resolved.execution_result["success"] is True


def test_approval_lifecycle_reject_transitions_to_rejected(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "100 + 200"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    reviewer = ReviewerIdentity(reviewer_id="rev-002", reviewer_name="Bob SecOps", role="SECURITY_REVIEWER")
    resolved = clean_approval_service.reject(approval.approval_id, reviewer=reviewer, reason="Rejected: untrusted parameters")

    assert resolved.status == ApprovalStatus.REJECTED
    assert resolved.resolution is not None
    assert resolved.resolution.decision == ApprovalDecision.REJECT
    assert resolved.execution_result is None


def test_approval_lifecycle_cancel_transitions_to_cancelled(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "100 + 200"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    cancelled = clean_approval_service.cancel(approval.approval_id, reason="User cancelled action")
    assert cancelled.status == ApprovalStatus.CANCELLED


def test_approval_lifecycle_expire_transitions_to_expired(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "100 + 200"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    expired = clean_approval_service.expire(approval.approval_id)
    assert expired.status == ApprovalStatus.EXPIRED


# ---------------------------------------------------------------------------
# 3. Terminal State Enforcement (Immutability)
# ---------------------------------------------------------------------------

def test_approval_terminal_state_approved_cannot_be_modified(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "5 * 5"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)
    reviewer = ReviewerIdentity(reviewer_id="rev-001", reviewer_name="Alice", role="SECURITY_REVIEWER")
    clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approved")

    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Re-approve")

    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.reject(approval.approval_id, reviewer=reviewer, reason="Reject after approve")

    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.cancel(approval.approval_id)


def test_approval_terminal_state_rejected_cannot_be_modified(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "5 * 5"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)
    reviewer = ReviewerIdentity(reviewer_id="rev-001", reviewer_name="Alice", role="SECURITY_REVIEWER")
    clean_approval_service.reject(approval.approval_id, reviewer=reviewer, reason="Rejected")

    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approve after reject")

    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.cancel(approval.approval_id)


def test_approval_terminal_state_cancelled_cannot_be_modified(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "5 * 5"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)
    clean_approval_service.cancel(approval.approval_id)

    reviewer = ReviewerIdentity(reviewer_id="rev-001", reviewer_name="Alice", role="SECURITY_REVIEWER")
    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approve after cancel")

    with pytest.raises(InvalidApprovalStateTransitionError):
        clean_approval_service.reject(approval.approval_id, reviewer=reviewer, reason="Reject after cancel")


# ---------------------------------------------------------------------------
# 4. Expiration Semantics
# ---------------------------------------------------------------------------

def test_approval_expired_cannot_be_approved(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "2 + 2"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=1.0)
    
    # Fast forward expiration check by modifying expires_at in DB
    from app.database.session import SessionLocal
    from app.models.models import ApprovalRequestModel
    from sqlalchemy import select
    with SessionLocal() as session:
        rec = session.scalar(select(ApprovalRequestModel).where(ApprovalRequestModel.approval_id == approval.approval_id))
        if rec:
            rec.expires_at = utc_now() - timedelta(seconds=10)
            session.commit()

    reviewer = ReviewerIdentity(reviewer_id="rev-001", reviewer_name="Alice", role="SECURITY_REVIEWER")
    with pytest.raises(ApprovalExpiredError):
        clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Late approve")


def test_approval_dynamic_expiration_on_fetch(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "2 + 2"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=1.0)
    
    from app.database.session import SessionLocal
    from app.models.models import ApprovalRequestModel
    from sqlalchemy import select
    with SessionLocal() as session:
        rec = session.scalar(select(ApprovalRequestModel).where(ApprovalRequestModel.approval_id == approval.approval_id))
        if rec:
            rec.expires_at = utc_now() - timedelta(seconds=10)
            session.commit()

    fetched = clean_approval_service.get_approval(approval.approval_id)
    assert fetched.status == ApprovalStatus.EXPIRED


# ---------------------------------------------------------------------------
# 5. Real Tool Execution on Approval (SEC-03 Remediation)
# ---------------------------------------------------------------------------

def test_approval_execution_calculator_on_approval(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "50 * 4"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    reviewer = ReviewerIdentity(reviewer_id="rev-calc", reviewer_name="Math Reviewer", role="SECURITY_REVIEWER")
    approved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approve math")

    assert approved.status == ApprovalStatus.APPROVED
    assert approved.execution_result is not None
    assert approved.execution_result["success"] is True
    assert approved.execution_result["result"]["result"] == 200.0


def test_approval_execution_filesystem_write_on_approval(clean_approval_service):
    eval_res = _make_eval_result(
        "filesystem",
        {"operation": "write", "path": "approval_output.txt", "content": "Approved by Human Reviewer"},
        action=ActionType.WRITE,
        category=ToolCategory.FILESYSTEM,
    )
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    reviewer = ReviewerIdentity(reviewer_id="rev-fs", reviewer_name="FS Reviewer", role="SECURITY_REVIEWER")
    approved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approve FS Write")

    assert approved.status == ApprovalStatus.APPROVED
    assert approved.execution_result is not None
    assert approved.execution_result["success"] is True
    assert approved.execution_result["result"]["operation"] == "write"
    assert approved.execution_result["result"]["bytes_written"] > 0


def test_approval_execution_command_echo_on_approval(clean_approval_service):
    eval_res = _make_eval_result(
        "command.restricted",
        {"command": "echo hello_from_approval"},
        action=ActionType.EXECUTE,
        category=ToolCategory.SYSTEM,
    )
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    reviewer = ReviewerIdentity(reviewer_id="rev-cmd", reviewer_name="Cmd Reviewer", role="SECURITY_REVIEWER")
    approved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approve Echo")

    assert approved.status == ApprovalStatus.APPROVED
    assert approved.execution_result is not None
    assert approved.execution_result["success"] is True
    assert "hello_from_approval" in approved.execution_result["result"]["stdout"]


def test_approval_execution_handles_tool_failure_gracefully(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "99 / 0"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    reviewer = ReviewerIdentity(reviewer_id="rev-calc", reviewer_name="Reviewer", role="SECURITY_REVIEWER")
    approved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Approve flawed calculation")

    assert approved.status == ApprovalStatus.APPROVED
    assert approved.execution_result is not None
    assert approved.execution_result["success"] is False
    err = approved.execution_result.get("error", "").lower()
    assert "division" in err or "zero" in err


def test_approval_execution_persisted_in_database(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "7 * 8"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)
    reviewer = ReviewerIdentity(reviewer_id="rev-db", reviewer_name="DB Reviewer", role="SECURITY_REVIEWER")
    clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="Persistence Test")

    fresh = clean_approval_service.repository.get_by_id(approval.approval_id)
    assert fresh is not None
    assert fresh.status == ApprovalStatus.APPROVED
    assert fresh.execution_result is not None
    assert fresh.execution_result["success"] is True
    assert fresh.execution_result["result"]["result"] == 56.0


# ---------------------------------------------------------------------------
# 6. RBAC Role Enforcement
# ---------------------------------------------------------------------------

def test_approval_rbac_viewer_cannot_approve(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "1 + 1"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    viewer = ReviewerIdentity(reviewer_id="rev-viewer", reviewer_name="Viewer User", role="VIEWER")
    with pytest.raises(AuthorizationDeniedError):
        clean_approval_service.approve(approval.approval_id, reviewer=viewer, reason="Attempted approve")


def test_approval_rbac_viewer_cannot_reject(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "1 + 1"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    viewer = ReviewerIdentity(reviewer_id="rev-viewer", reviewer_name="Viewer User", role="VIEWER")
    with pytest.raises(AuthorizationDeniedError):
        clean_approval_service.reject(approval.approval_id, reviewer=viewer, reason="Attempted reject")


def test_approval_rbac_identity_with_resolve_permission_succeeds(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "12 + 12"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    sec_reviewer = UserIdentity(
        user_id="usr-sec",
        username="sec_lead",
        display_name="Security Lead",
        roles=(Role.SECURITY_REVIEWER,),
    )
    approved = clean_approval_service.approve_with_identity(
        approval.approval_id, identity=sec_reviewer, reason="Authorized approval"
    )
    assert approved.status == ApprovalStatus.APPROVED


# ---------------------------------------------------------------------------
# 7. REST API Endpoints
# ---------------------------------------------------------------------------

def test_approval_api_get_list(client, clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "1 + 2"})
    clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    res = client.get("/api/v1/security/approvals")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_approval_api_get_single(client, clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "1 + 2"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    res = client.get(f"/api/v1/security/approvals/{approval.approval_id}")
    assert res.status_code == 200
    assert res.json()["approval_id"] == approval.approval_id
    assert res.json()["status"] == "PENDING"


def test_approval_api_get_nonexistent_returns_404(client, clean_approval_service):
    res = client.get("/api/v1/security/approvals/app-nonexistent-12345")
    assert res.status_code == 404


def test_approval_api_post_approve_success(client, clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "9 * 9"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    payload = {
        "reviewer_id": "rev-api-001",
        "reviewer_name": "API Reviewer",
        "role": "SECURITY_REVIEWER",
        "reason": "Approved via REST endpoint",
    }
    res = client.post(f"/api/v1/security/approvals/{approval.approval_id}/approve", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "APPROVED"
    assert data["execution_result"] is not None
    assert data["execution_result"]["success"] is True
    assert data["execution_result"]["result"]["result"] == 81.0


def test_approval_api_post_reject_success(client, clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "9 * 9"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    payload = {
        "reviewer_id": "rev-api-001",
        "reviewer_name": "API Reviewer",
        "role": "SECURITY_REVIEWER",
        "reason": "Rejected via REST endpoint",
    }
    res = client.post(f"/api/v1/security/approvals/{approval.approval_id}/reject", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "REJECTED"


def test_approval_api_post_cancel_success(client, clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "9 * 9"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    payload = {"reason": "Cancelled via REST endpoint"}
    res = client.post(f"/api/v1/security/approvals/{approval.approval_id}/cancel", json=payload)
    assert res.status_code == 200
    assert res.json()["status"] == "CANCELLED"


# ---------------------------------------------------------------------------
# 8. Request Binding & Tamper Detection
# ---------------------------------------------------------------------------

def test_approval_validation_against_tampered_request(clean_approval_service):
    eval_res = _make_eval_result("calculator", {"expression": "10 + 20"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)
    reviewer = ReviewerIdentity(reviewer_id="rev-01", reviewer_name="Rev", role="SECURITY_REVIEWER")
    approved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="OK")

    assert clean_approval_service.validate_against_request(approved, eval_res.request) is True

    tampered_tool = eval_res.request.model_copy(update={"tool_name": "filesystem.write"})
    assert clean_approval_service.validate_against_request(approved, tampered_tool) is False

    tampered_params = eval_res.request.model_copy(update={"parameters": {"expression": "1000 + 2000"}})
    assert clean_approval_service.validate_against_request(approved, tampered_params) is False


def test_approval_is_valid_helper_checks(clean_approval_service):
    assert clean_approval_service.is_valid("app-fake-999") is False
    assert clean_approval_service.is_valid("") is False
    assert clean_approval_service.is_valid(None) is False

    eval_res = _make_eval_result("calculator", {"expression": "1 + 1"})
    approval = clean_approval_service.create_approval(eval_res, ttl_seconds=300.0)

    assert clean_approval_service.is_valid(approval.approval_id) is False

    reviewer = ReviewerIdentity(reviewer_id="rev-01", reviewer_name="Rev", role="SECURITY_REVIEWER")
    approved = clean_approval_service.approve(approval.approval_id, reviewer=reviewer, reason="OK")

    assert clean_approval_service.is_valid(approval.approval_id) is True
